# qemu system模式

## 准备
https://github.com/dhruvvyas90/qemu-rpi-kernel


sudo apt-get install uml-utilities bridge-utils
sudo tunctl -t tap0 -u `whoami`
sudo ifconfig tap0 10.0.2.1/24 

sudo ifconfig eth0 10.0.2.15/24

scp -P 2222 gdbserver pi@192.168.117.132:/home/pi/

ssh -CfNg -L 1234:127.0.0.1:1234 pi@10.0.2.15
ssh -CfNg -L 2222:127.0.0.1:22 pi@10.0.2.15

1、使用默认账户(pi)密码(raspberry)登录raspberry
2、开启 ssh 服务，并设置开机启动
$ sudo service ssh start
$ sudo update-rc.d ssh enable


## 执行

qemu-system-arm \
  -M versatilepb \
  -cpu arm1176 \
  -m 256 \
  -drive "file=2021-05-07-raspios-buster-armhf-lite.img,if=none,index=0,media=disk,format=raw,id=disk0" \
  -device "virtio-blk-pci,drive=disk0,disable-modern=on,disable-legacy=off" \
  -net nic -net "tap,ifname=tap0,script=no,downscript=no"\ #nic和tap模式
  -net "user,hostfwd=tcp::2222-:22" \ # 为 ssh 预留，将qemu的22端口转5022端口
  -net user,hostfwd=tcp::1234-:1234 \ # 为 gdbserver预留
  -dtb versatile-pb-buster-5.4.51.dtb \
  -kernel kernel-qemu-5.4.51-buster \
  -append 'root=/dev/vda2 panic=1' \
  -no-reboot

## Ref
http://www.gandalf.site/2018/12/iotqemuiot.html