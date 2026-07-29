async function loadPackets() {

    const response = await fetch("http://127.0.0.1:8000/packets");
    const packets = await response.json();

    const tbody = document.getElementById("packetTableBody");

    tbody.innerHTML = "";

    let tcp = 0;
    let udp = 0;
    let icmp = 0;

    packets.forEach(packet => {

        let protocolName = packet.protocol;

        if(packet.protocol == "6"){
            protocolName = "TCP";
            tcp++;
        }
        else if(packet.protocol == "17"){
            protocolName = "UDP";
            udp++;
        }
        else if(packet.protocol == "1"){
            protocolName = "ICMP";
            icmp++;
        }

        let alertColor = "lime";

        if(packet.alert === "Suspicious")
            alertColor = "red";

        else if(packet.alert === "ICMP")
            alertColor = "orange";

        const row = `
        <tr>

            <td>${packet.id}</td>
            <td>${packet.source_ip}</td>
            <td>${packet.destination_ip}</td>
            <td>${protocolName}</td>
            <td>${packet.source_port}</td>
            <td>${packet.destination_port}</td>

            <td>
                <span style="
                background:${alertColor};
                color:white;
                padding:5px 10px;
                border-radius:20px;">
                ${packet.alert}
                </span>
            </td>

            <td>${packet.attack_type}</td>

        </tr>
        `;

        tbody.innerHTML += row;

    });

    document.getElementById("totalPackets").innerText = packets.length;
    document.getElementById("tcpCount").innerText = tcp;
    document.getElementById("udpCount").innerText = udp;
    document.getElementById("icmpCount").innerText = icmp;

}

loadPackets();

setInterval(loadPackets,3000);
