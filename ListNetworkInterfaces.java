import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import java.util.List;

public class ListNetworkInterfaces {

    public static void main(String[] args) {
        try {
            // Step 1: List all available network interfaces
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

            if (devices == null || devices.isEmpty()) {
                System.out.println("No network devices found.");
                return;
            }

            // Step 2: Print each network interface's name and description
            System.out.println("Network interfaces found:");
            for (PcapNetworkInterface device : devices) {
                System.out.println(device.getName() + " - " + device.getDescription());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
