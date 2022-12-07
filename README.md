# OCULii EAGLE mmwave radar network packets decode

<img src="assets/image-20221207131003592.png" alt="image-20221207131003592" style="zoom:50%;" />

<img src="assets/image-20221207131023670.png" alt="image-20221207131023670" style="zoom:80%;" />

## functions

1. when ptp sync function is running, generate pointcloud(.pcd/.npz) according to network packets, and name a pointcloud frame as timestamp_unix
2. decode PTP timestamp
3. decode pointcloud

## introduction

![image-20221207130058018](assets/image-20221207130058018.png)

## Handshake Packet

![image-20221207130112123](assets/image-20221207130112123.png)

## Body Packet

![image-20221207130121078](assets/image-20221207130121078.png)

### Header Block

![image-20221207130131784](assets/image-20221207130131784.png)

### Detection Block

![image-20221207130857235](assets/image-20221207130857235.png)

### Tracker Block

![image-20221207130940364](assets/image-20221207130940364.png)

### Footer Block

![image-20221207130954629](assets/image-20221207130954629.png)