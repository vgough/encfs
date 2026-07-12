# rfuse3 并发与背压实现说明

本文档描述最近引入的多 worker FUSE 请求处理与背压机制，方便后续维护与扩展。

## 目标
- 在 `worker_count > 1` 时并行处理耗时 / IO 密集 FUSE 请求，降低单线程瓶颈。
- 提供统一的 in-flight（排队+运行）计数，实现 `max_background` 背压，避免过量堆积内存与请求。
- 渐进迁移：保持单线程语义回退路径不变；逐步将各 opcode 移入 worker 体系。

## 背景 & 动机
### 传统单线程模型的问题
历史上 rfuse3（以及许多 fuse binding 的最简实现）在用户态有一个单线程循环：读取 `/dev/fuse` → 匹配 opcode → 为每个请求 spawn 一个异步任务（或同步处理）。瓶颈主要出现在：
1. 某些耗时操作（远程存储、网络、磁盘 IO）阻塞导致内核缓冲区请求堆积；
2. 高频 LOOKUP/GETATTR/READ 在目录遍历或大规模并发客户端场景下争抢同一个调度点；
3. 没有统一的“压力阈值”，大量请求体（尤其 WRITE / READDIR）在用户态复制占用内存；
4. 缺少对未来特性（interrupt、per-inode 串行）插入的结构化扩展点。

### 与 libfuse 的对比
libfuse 多线程模式（`-o multithreaded` 或默认）是“一个 reader + N worker 线程处理逻辑”的典型模型；内核本身支持并发提交请求（最大并发受内核 `fuse_conn->max_background` 等限制）。我们在 rfuse3 中复刻类似模式，但：
- 依旧保持异步 runtime 兼容（tokio / async-io）；
- 使用 mpsc + async 任务代替裸线程（减少上下文切换 & 更易组合异步 IO）；
- 引入明确的 in-flight 计数与 gating，以避免 runtime 层面无限扩散任务。

### 为什么使用延迟初始化（deferred worker init）
FUSE_INIT 前内核与用户态尚未协商好参数（如最大写入 `max_write`）。我们需要先完成 INIT 才能：
1. 得到动态的最大写缓冲尺寸设置读取 buffer；
2. 决定是否启动并发（某些场景仅在握手后读取 mount options 动态调整 worker 数）。

### InHeaderLite 的引入
`fuse_in_header` 在当前实现里以反序列化 buffer 形式存在；如果直接 move 进 `WorkItem`，后续 inline 路径或日志还可能需要原 header。复制一个精简只读结构体（nodeid/uid/gid/pid）即可满足绝大多数 worker 逻辑（权限判断、路径上下文），避免不必要的大结构 clone / 生命周期耦合。

### 选择 backpressure 策略的考虑
内核已有自己的 `max_background`（协商阶段返回的值）控制内核→用户态未完成请求上限。但用户态仍可能继续读取并复制数据进入用户空间队列导致内存压力。双层控制的意义：
- 用户态 `max_background` 可以更紧（<= 内核值），对大对象（WRITE/READDIR large payload）进行提前限流；
- 当底层存储延迟突增时，通过减少新请求读取，给正在执行的请求（特别是可能需要内核立即响应的 flush/stat 等）腾出资源。

### 与 per-inode 串行的关系
本次实现先完成粗粒度并行 + 背压；per-inode 串行会基于 `WorkItem` 增加一个可选调度层：
1. 提交前计算 key（如 `(parent_inode, name)` 或 `inode`）；
2. 使用 `DashMap<InodeKey, Queue>` 或 `parking_lot::Mutex` + FIFO；
3. 当前 key 正在执行则只入队；结束时唤醒下一个；
这层逻辑只需要在 `Workers::submit` 前后插入，不破坏现有 worker 消费循环。

### 错误计数回收的重要性
对包括参数解析失败、结构体截断等“早期失败”路径必须进行 `inflight -= 1`，否则 dispatch 永远认为高水位，造成“永久阻塞”或“实际没有任务仍然背压”现象，因此专门补丁确保所有 return 之前都减计数并 notify。

## Kernel 交互与约束
| 方面 | 内核 / 协商字段 | 用户态对应 | 备注 |
|------|----------------|-----------|------|
| 最大并行后台请求 | `max_background` | `Session.max_background` (可更紧) | 内核侧值仍决定内核挂起数量上限 |
| 写入最大大小 | `max_write` (init out) | 计算 read buffer 尺寸 | 提前设定 data_buffer 大小降低重复 realloc |
| 请求唯一 ID | header.unique | WorkItem.unique | interrupt / 取消需要映射 |
| 中断请求 | FUSE_INTERRUPT | (待实现) | 需记录 unique->AbortHandle |

## 调参指南（初步）
| 工作负载特征 | 建议 worker_count | 建议 max_background | 原因 |
|---------------|------------------|--------------------|------|
大量小文件元数据 (stat / list) | CPU 核心数 (或核心数-1) | 2~4 * worker_count | LOOKUP/GETATTR 轻量，增加并行度降低排队 |
顺序/大文件读 | 2~4 | 64~128 | 避免过度争抢 cache；读可较大 chunk |
高并发随机写 (远程存储) | 4~8 | 32~64 | 写延迟高，需要一定排队隐藏 RTT，但避免堆积太多 payload |
混合读写 + 目录列举 | 4~6 | 64~96 | 折中设置，减少 readdir 大 buffer 的爆发 |

经验：先用保守值运行并通过 tracing 统计“阻塞次数/平均 in-flight”再逐步放宽。

## 监控指标建议（尚未实现）
- 当前 in-flight (`inflight.load()`)
- 高水位阻塞次数（dispatch 进入等待的计数）
- 每 opcode 平均处理耗时/队列等待时间（时间戳记录）
- 错误类型分布（EINVAL/ENOSYS 等）
- 95/99 延迟（需要环形缓冲 + 简单直方图）

## 设计取舍 (Trade-offs)
| 方案 | 取舍 | 选择原因 |
|------|------|----------|
| 每请求直接 spawn（现方案） vs 线程持久处理 | spawn 有调度开销 | 异步 runtime 下 spawn 成本可接受，代码简单，便于添加 tracing span |
| Vec<u8> 拷贝 vs 零拷贝借用原缓冲 | 拷贝增加内存/CPU | 先实现正确性与隔离，后续可引入 `Bytes` 或 slab 分配池 |
| 单层队列 vs 按 opcode 分类队列 | 单层可能被某类请求充满 | 简化；后续可在 submit 前根据 opcode 做优先级/分类 |
| 原子计数 + Notify vs 信号量库 | 需手动保证减计数 | 减少依赖；语义透明（AcqRel + while-loop gating） |

## 未来可插拔特性放置点
| 特性 | 推荐实现位置 | 说明 |
|------|--------------|------|
| Interrupt 取消 | Workers::submit 后注册 / worker 完成后清理 | 使用 `futures::future::AbortHandle` 或 runtime Cancel API |
| Per-inode 串行 | Workers::submit 之前 | 封装一个 limiter，决定入队或排队链表 |
| 优先级调度 | Workers::submit 之前 | 多个队列 + 简单权重/aging |
| Metrics | worker_* 尾部 + dispatch 循环 | 采样或累加计数器 |
| 零拷贝 | WorkItem.data 类型替换 | 需要保证生命周期跨 worker 安全 |

## FAQ
Q: 背压是否可能导致内核侧“看起来空闲”但用户态阻塞？
A: 会，但这是设计上主动限速。当用户态资源（内存/线程）处于高水位，宁愿让内核阻塞请求（内核已有上界控制）也不希望用户态复制与排队过多 payload。

Q: inflight 是否统计仍在 channel 中但尚未被 worker poll 的请求？
A: 是（排队+执行均算），这样阈值表达总资源占用而非仅运行中数量。

Q: 如果 channel send 失败怎么处理？
A: 当前回滚 inflight 并 notify；失败一般意味着 shutdown/worker 已退出。

Q: READ/WRITE 大数据是否可能挤占队列导致元数据延迟？
A: 当前无优先级；可后续引入基于 opcode 的多队列或优先级调度器缓解。

---

## 结构概览
```
Session
  ├─ workers: Option<Workers<FS>>
  ├─ inflight: AtomicUsize (Arc)
  ├─ inflight_notify: async_notify::Notify
  └─ dispatch() 读取 /dev/fuse 并分派

Workers
  ├─ senders: Vec<mpsc::Sender<WorkItem>>  (有界 channel)
  ├─ handles: JoinHandle<()>               (保持任务不被 drop)
  └─ submit(WorkItem) 轮询选择下标并入队

DispatchCtx (Arc 共享给每个 worker task)
  ├─ fs: Arc<FS>
  ├─ resp: UnboundedSender<FuseData>

WorkItem
  ├─ unique
  ├─ opcode (u32, 直接来自内核 header)
  ├─ in_header: InHeaderLite (避免 move 原始 header)
  └─ data: Vec<u8>  (请求体拷贝)
  └─ _inflight_guard: InflightGuard (自动管理计数，一个请求对应一个计数)
```

## 生命周期
1. `dispatch()` 首次进入先完成 FUSE_INIT（保持原逻辑）。
2. 若 `worker_count > 1`，调用 `ensure_workers()` 延迟创建 worker 池，构造共享 `DispatchCtx`。
3. 进入主循环：
   - 若 workers 启用：在读取下一条请求前检查 `inflight >= max_background`，必要时 `await inflight_notify` 等待释放。
   - 读取 header+body；解析 opcode；构造 `WorkItem`；调用 `Workers::submit`：
     - `submit` 先 `inflight += 1` 再尝试发送；失败（channel 关闭）则回滚并通知。
   - 对已迁移 opcode（LOOKUP / GETATTR / OPEN / READ / WRITE / READDIR）不再走 inline 处理；其余 opcode 继续旧路径。
4. Worker 侧 `process_work_item` 匹配 opcode → 调用对应 `worker_*` 实现。
5. `worker_*`：
   - 解析参数；若早期解析失败：发送错误回复 + `inflight -= 1` + `notify()`。
   - spawn 内部异步任务执行业务逻辑；完成后发送响应，`inflight -= 1` + `notify()`。

## 背压实现细节
- 计数字段：`Session.inflight: Arc<AtomicUsize>`。
- 加计数：`Workers::submit` 入队前；失败回滚。
- 减计数：所有 worker 任务的正常完成与所有早期错误返回路径。
- 读阻塞：`dispatch` 循环顶部（仅在 workers_active 时）。
- 通知：`async_notify::Notify`，在减计数后 `notify()`；阻塞端循环 `while inflight >= max_background { notified().await }`。

## 已迁移的 opcode
​	所有已实现的opcode都已迁移过去。FS应该在启动的时候就设置好使用单线程模式还是多worker模式，不能使用混杂模式。

## 线程安全 & 同步
- FS 需要 `Send + Sync + 'static`，因此在 `Session` 泛型约束中已经添加。
- 当前未实现 per-inode 顺序控制；未来可在提交前为 inode/目录名计算 key，借助 `DashMap<InodeKey, MutexQueue>` 实现串行。

## 错误处理策略
- 参数解析错误：直接返回 `EINVAL`（保持原逻辑）并减计数；不再继续。
- 未支持 opcode：worker 中仅日志，不发送回复（因为原 inline 路径仍会处理）——一旦全部迁移，需要改为发送 ENOSYS。

## 性能注意点与后续优化
1. 多次拷贝：`WorkItem.data` 对于 READ/WRITE/READDIR 可能较大，后续可改为引用原共享 buffer + 引用计数（例如 Bytes / Arc<[u8]>）。
2. 大量 worker spawn 嵌套：当前 worker 线程再 spawn 实际业务 future，可合并（直接在 worker loop 内执行）减少一次调度，但保留 span 粒度更清晰。
3. 背压阈值策略：目前简单阈值；可加二级阈值（软/硬）或自适应（基于平均执行时间估计）。
4. READDIR 构造目录项缓冲多次 push + padding，可考虑自定义 writer 减少重复 bounds 检查。
5. 未来 interrupt：需要建立 `Arc<Mutex<HashMap<u64, AbortHandle>>>`，在 submit 增加记录，在完成/错误时清除。

## 代码热区索引
- 结构体与核心逻辑：`src/raw/session.rs`
  - Session: 约第 230 行附近
  - Workers / DispatchCtx / WorkItem: Session 定义后
  - process_work_item / worker_*: ~300-600 行区间（具体随增删变动）
  - dispatch(): 搜索 `async fn dispatch`

## 回退与兼容
- `worker_count <= 1`：完全保持旧行为，无 inflight gating；所有请求仍 inline spawn，确保现有使用者不受影响。
- 未引入任何不兼容对外 API 变更；新增 builder 样式 `with_workers`（可选）。

## 使用示例（伪代码）
```rust
let session = Session::new(mount_options)
    .with_workers(4, 1024); // 4 worker, 背压阈值 1024
session.mount(fs, mount_point).await?;
```

## 待办清单
- [x] 迁移剩余耗时 opcode（WRITE 已迁，接下来建议：SETATTR / FSYNC / RELEASE / CREATE 等）
- [ ] interrupt 支持
- [ ] per-inode 串行（可选）
- [ ] WorkItem 零拷贝优化
- [x] Inline opcode 统一纳入 inflight 或全部迁移
- [ ] 指标/监控：当前 in_flight，高水位阻塞次数

## 风险与测试建议
- 测试高并发小文件创建/读取的稳定性（LOOKUP/OPEN/READ/WRITE 路径）。
- 压测背压触发行为：调整 `max_background`=N，确认内核请求不会无限堆积（可通过加 tracing 统计阻塞次数）。
- 模拟错误输入（截断数据）确保计数回收。

---
如需扩展请在本文档追加章节，保持团队共享认知。
