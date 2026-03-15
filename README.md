# own_docker_project

To setup the alpine rootfs, run this script:

```
chmod +x setup_rootfs.sh && ./setup_rootfs.sh
```

Then you can run this python code, to run the simple the simple container:
```
sudo python3 src/main.py
```

To move the stress.py to check the Cgroups, run this:
```
cp src/stress.py rootfs/root/stress.py
```

Also it may be needed to remove the isolation of network from the main.py code, to install python3

Then run it by:
```
python3 stress.py
```