import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;

import javax.swing.*;
import java.awt.*;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Set;

public class StaticPacketFilteringFirewall {

    // Define filtering rules with multiple IPs and ports
    private static final Set<String> BLOCKED_IPS = new HashSet<>();
    private static final Set<Integer> BLOCKED_PORTS = new HashSet<>();

    // GUI Components
    private static JTextArea outputArea;
    private static JButton startButton;
    private static JButton stopButton;
    private static volatile boolean capturing = false;

    public static void main(String[] args) {
        // Add IPs and ports to block
        BLOCKED_IPS.add("192.168.165.255");  // Example IP to block
        BLOCKED_IPS.add("192.168.1.100");    // Another IP to block

        BLOCKED_PORTS.add(8080);  // Example port to block
        BLOCKED_PORTS.add(80);    // Another port to block
        BLOCKED_PORTS.add(5353);  // Another port to block

        // Set up the GUI
        setupGUI();
    }

    private static void setupGUI() {
        JFrame frame = new JFrame("Static Packet Filtering Firewall");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        // Text area to display packet information
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);

        // Start and Stop buttons
        startButton = new JButton("Start Capture");
        stopButton = new JButton("Stop Capture");
        stopButton.setEnabled(false);

        // Panel for buttons
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(startButton);
        buttonPanel.add(stopButton);

        // Add components to the frame
        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(buttonPanel, BorderLayout.SOUTH);

        // Button action listeners
        startButton.addActionListener(e -> startPacketCapture());
        stopButton.addActionListener(e -> stopPacketCapture());

        frame.setVisible(true);
    }

    private static void startPacketCapture() {
        capturing = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        outputArea.append("Starting packet capture...\n");

        // Start capturing packets in a new thread
        new Thread(() -> capturePackets()).start();
    }

    private static void stopPacketCapture() {
        capturing = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        outputArea.append("Stopping packet capture...\n");
    }

    private static void capturePackets() {
        try {
            // List available network interfaces
            PcapNetworkInterface device = null;
            java.util.List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            for (PcapNetworkInterface dev : allDevs) {
                outputArea.append("Found network device: " + dev.getName() + " - " + dev.getDescription() + "\n");
                // Automatically select the Wi-Fi adapter (you may change this based on your network interface)
                if (dev.getDescription() != null && dev.getDescription().contains("Realtek")) {
                    device = dev;
                    break;
                }
            }

            if (device == null) {
                outputArea.append("No suitable network device found\n");
                return;
            }

            // Step 2: Open the network interface for capturing
            int snapLen = 65536; // Capture all packet length
            PcapHandle handle = device.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            // Step 3: Capture and filter packets
            handle.loop(-1, packet -> {
                if (!capturing) {
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                    return;
                }

                // Print basic packet info
                StringBuilder packetInfo = new StringBuilder();

                // Check for IP packets
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                    InetAddress srcAddr = ipPacket.getHeader().getSrcAddr();
                    InetAddress dstAddr = ipPacket.getHeader().getDstAddr();

                    packetInfo.append("IP Packet - Src IP: ").append(srcAddr.getHostAddress())
                            .append(", Dst IP: ").append(dstAddr.getHostAddress());

                    // Check if the source or destination IP is blocked
                    if (BLOCKED_IPS.contains(srcAddr.getHostAddress()) || BLOCKED_IPS.contains(dstAddr.getHostAddress())) {
                        packetInfo.append(" [BLOCKED]\n");
                        outputArea.append(packetInfo.toString());
                        return; // Drop the packet
                    }
                }

                // Check for TCP packets
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                    int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                    packetInfo.append(" | TCP Packet - Src Port: ").append(srcPort)
                            .append(", Dst Port: ").append(dstPort);

                    // Check if the source or destination port is blocked
                    if (BLOCKED_PORTS.contains(srcPort) || BLOCKED_PORTS.contains(dstPort)) {
                        packetInfo.append(" [BLOCKED]\n");
                        outputArea.append(packetInfo.toString());
                        return; // Drop the packet
                    }
                }

                // Check for UDP packets
                if (packet.contains(UdpPacket.class)) {
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                    int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                    packetInfo.append(" | UDP Packet - Src Port: ").append(srcPort)
                            .append(", Dst Port: ").append(dstPort);

                    // Check if the source or destination port is blocked
                    if (BLOCKED_PORTS.contains(srcPort) || BLOCKED_PORTS.contains(dstPort)) {
                        packetInfo.append(" [BLOCKED]\n");
                        outputArea.append(packetInfo.toString());
                        return; // Drop the packet
                    }
                }

                // Check for ICMP packets (used by ping)
                if (packet.contains(IcmpV4CommonPacket.class)) {
                    packetInfo.append(" | ICMP Packet (Ping)");
                }

                // If the packet is allowed
                packetInfo.append(" [ALLOWED]\n");
                outputArea.append(packetInfo.toString());
            });

            // Close the handle after stopping
            handle.close();

        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            e.printStackTrace();
            outputArea.append("Error capturing packets: " + e.getMessage() + "\n");
        }
    }
}
