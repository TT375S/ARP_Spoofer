# ARP_Spoofer
二つの端末のIPアドレスとMACアドレスを指定すると、ARPスプーフィングを行い、パケットを中継&記録してファイルにダンプします。  
MITM攻撃ですので普通は改竄もできますがこのプログラムには実装していません。盗聴だけです。

# Fork
[ルーター自作でわかるパケットの流れ](http://gihyo.jp/book/2011/978-4-7741-4745-1/support)という本のサンプルコードのARP送信部分を参考にしています

# Usage
Ubuntuでしか動作を確認していません。  
BSDとかではネットワークデバイスの扱いが異なるらしいので多分動きません。Linuxだけです。  
VMで使う場合は、ブリッジ接続にしプロミスキャスモードをオンにしないと、外からの通信がVMに届きません。(ゲストの仮想NICのMACaddr宛てのものはホストPCのNICが捨ててしまうので。)  
  
`Src/Arp`に移動して`make`したあと、  
`$ sudo ./arpspoofing <ip_addr_a> <ip_add_b> <mac_addr_a> <mac_addr_b>`  
とすると起動できます。  
`pcapdump-(日時).pcap`というファイルとして、MITMで中継したパケットをダンプします。

中継パケットの情報をいちいち表示するverboseモードフラグ(1)と、使用するインターフェース名(enp0s3)はmain.cのmain関数内の先頭行にハードコードしてあります。  
UbuntuのVMでネットワークの設定をブリッジアダプターで使用するなら、変える必要はないと思います  
  
`Src/Arp/ARPSpoofing`は何だったんだか忘れましたがコミットログ見るとたぶんARPリクエスト送ってARPスプーフィングができているかの確認用？  
`Src/Bridge`もARPリクエストが送れるかの確認用だったっぽいのでこいつらは無視してください。

# 
