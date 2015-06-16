docker run -d --name="drone-ci" \
 -p 8080:8080 \
 -v /var/lib/drone/ \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -v /home/core/droneio/drone.sqlite:/var/lib/drone/drone.sqlite \
 encfs_drone
