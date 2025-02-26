import org.pcap4j.core.*
import org.pcap4j.packet.*
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.namednumber.*
import java.net.InetAddress
import java.util.concurrent.TimeUnit

// Function to get user input for WAP IP Address
fun getWapIp(): String {
    println("Enter WAP IP Address to check for potential Water Hole attack:")
    return readLine()!!
}

// Function to perform a basic scan of the network and check for DNS anomalies
fun detectWaterHoleAttack(wapIp: String) {
    println("Checking WAP IP: $wapIp for potential Water Hole attack...")
    
    // Use pcap4j to sniff packets from the network
    println("Starting packet sniffing...")
    val networkInterface = Pcaps.findAllDevs().firstOrNull { it.isUp }
    
    if (networkInterface != null) {
        val handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000)
        
        val filter = "host $wapIp"
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE)
        
        // Sniff packets for 60 seconds
        val timeout = TimeUnit.SECONDS.toMillis(60)
        val endTime = System.currentTimeMillis() + timeout
        while (System.currentTimeMillis() < endTime) {
            handle.loop(1) { packet -> analyzePacket(packet) }
        }
    } else {
        println("No network interface found!")
    }
}

// Analyze each packet to look for DNS anomalies or suspicious patterns
fun analyzePacket(packet: PcapPacket) {
    if (packet.has(DnsPacket::class.java)) {
        val dnsPacket = packet.get(DnsPacket::class.java)
        
        // Check if it's a DNS request or response
        if (dnsPacket.header.opCode == DnsOpCode.QUERY) {
            val query = dnsPacket.questions.firstOrNull()?.name?.toString()
            if (query != null) {
                println("DNS Query: $query")
                checkForSuspiciousDns(query)
            }
        } else if (dnsPacket.header.opCode == DnsOpCode.RESPONSE) {
            val response = dnsPacket.answerRecords.joinToString(", ") { it.toString() }
            println("DNS Response: $response")
            checkForSuspiciousDns(response)
        }
    }
}

// Function to identify suspicious DNS traffic
fun checkForSuspiciousDns(dnsEntry: String) {
    val suspiciousDomains = listOf("evilsite.com", "fake.com", "malicious.com")
    
    if (suspiciousDomains.any { dnsEntry.contains(it) }) {
        println("WARNING: Suspicious DNS detected! $dnsEntry")
    } else {
        println("DNS traffic seems normal: $dnsEntry")
    }
}

// Main function
fun main() {
    val wapIp = getWapIp()  // Get the WAP IP address from the user
    detectWaterHoleAttack(wapIp)  // Start detection
}
