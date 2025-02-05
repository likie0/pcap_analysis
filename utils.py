import dpkt, time, csv, socket, datetime, json, re
import numpy as np

# Constants for packet filtering
LEN_FILTER_UPPER = 10000  # Upper limit for packet length filtering
LEN_FILTER_LOWER = 70    # Lower limit for packet length filtering
MTU = 1500               # Maximum Transmission Unit

def filtered(frame, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper):
    """
    Filters packets based on specified criteria (only for IPv4).

    Parameters:
    - frame: The raw packet data.
    - mode: The mode of operation. Supports 'NORMAL' (Ethernet frame) or 'RAW_IP' (raw IP packet).
    - L4_type: The Layer 4 protocol type (e.g., 'tcp', 'udp', 'icmp').
    - ip_lst: List of allowed (source, destination) IP pairs.
    - port_lst: List of allowed (source, destination) port pairs.
    - len_filter_lower: Lower bound for packet length filtering.
    - len_filter_upper: Upper bound for packet length filtering.

    Returns:
    - The filtered IP packet object if it meets the criteria, otherwise None.
    """
    if mode == 'NORMAL':
        try:
            ip = dpkt.ethernet.Ethernet(frame).ip  # Extract IP layer from Ethernet frame
        except Exception as e:  # Handle exceptions for non-IPv4 packets (e.g., IPv6)
            return None
    elif mode == 'RAW_IP':
        try:
            ip = dpkt.ip.IP(frame)  # Parse raw IP packet
        except dpkt.dpkt.NeedData:
            print("Need more data")
            return None
        except dpkt.dpkt.UnpackError:
            print("Unpack Error: invalid header length")
            return None
    else:
        raise Exception("Input Mode Error: only support 'NORMAL' and 'RAW_IP'")

    # Extract source and destination IP addresses
    ip_src = socket.inet_ntoa(ip.src)
    ip_dst = socket.inet_ntoa(ip.dst)

    # Check if the IP pair is in the allowed list
    if not any((ip_src, ip_dst) == (src, dst) for (src, dst) in ip_lst):
        return None

    sport, dport = None, None
    if L4_type != 'icmp':  # Extract source and destination ports for TCP/UDP
        try:
            sport = ip.data.sport
            dport = ip.data.dport
        except Exception as e:
            return None

    # Check if the port pair is in the allowed list
    flag = False
    for (src_p, dst_p) in port_lst:
        if src_p is None and dst_p is not None and dport == dst_p:
            flag = True
        elif src_p is not None and dst_p is None and sport == src_p:
            flag = True
        elif src_p is None and dst_p is None:  # No port restriction
            flag = True
    if not flag:
        return None

    # Filter based on packet length
    if ip.len < len_filter_lower:
        return None
    if len_filter_upper != LEN_FILTER_UPPER and ip.len > len_filter_upper:
        return None

    # Validate the Layer 4 protocol type(icmp is actually a L3 protocol)
    if L4_type == 'udp':
        udp = ip.data
        if not isinstance(udp, dpkt.udp.UDP):
            return None
    elif L4_type == 'tcp':
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return None
    elif L4_type == 'icmp': 
        icmp = ip.data
        if not isinstance(icmp, dpkt.icmp.ICMP):
            return None
    else:
        raise Exception("L4 protocol type Error: only support tcp/udp/icmp")

    return ip


def snd_rcv_match_ipid(snd_pcap_path, rcv_pcap_path, mode, L4_type, ip_lst, port_lst, end_time, len_filter_lower=LEN_FILTER_LOWER, len_filter_upper=LEN_FILTER_UPPER):
    """
    Matches sending and receiving packets based on IPID.

    Parameters:
    - snd_pcap_path: Path to the sending-side PCAP file.
    - rcv_pcap_path: Path to the receiving-side PCAP file.
    - mode: The mode of operation (see `filtered` function).
    - L4_type: The Layer 4 protocol type (see `filtered` function).
    - ip_lst: List of allowed (source, destination) IP pairs (see `filtered` function).
    - port_lst: List of allowed (source, destination) port pairs (see `filtered` function).
    - end_time: The duration for matching packets (in seconds).
    - len_filter_lower: Lower bound for packet length filtering (optional).
    - len_filter_upper: Upper bound for packet length filtering (optional).

    Returns:
    - A list of tuples containing (sending timestamp, receiving timestamp, IP layer length).
    - The first world time (timestamp of the first packet).
    """
    start = time.perf_counter()
    arrival_time_utc, time2end = None, None

    def seq_lt(seq1, seq2):
        """
        Helper function to compare sequence numbers considering wrap-around.
        """
        if seq1 < seq2:
            return seq2 - seq1 < 32768
        else:
            return seq1 - seq2 >= 32768

    snd_f = open(snd_pcap_path, 'rb')
    rcv_f = open(rcv_pcap_path, 'rb')
    snd_reader = dpkt.pcap.Reader(snd_f)
    rcv_reader = dpkt.pcap.Reader(rcv_f)
    snd_idx, rcv_idx, rcv_filter_sum, loss_sum = 0, 0, 1, 0

    rcv_end = False
    snd_rcv_lst = []
    OOO_buffer = [None] * 65536  # Out-of-Order buffer
    snd_lower, snd_upper = None, None
    first_world_time = None

    # Find the first valid packet on the receiving side
    for ts_rcv, rcv in rcv_reader:
        rcv_idx += 1
        ip_rcv = filtered(rcv, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)
        if ip_rcv is not None:
            break

    for ts_snd, snd in snd_reader:
        arrival_time_utc = datetime.datetime.fromtimestamp(ts_snd, datetime.timezone.utc)
        if rcv_end or (time2end is not None and arrival_time_utc >= time2end):
            break

        snd_idx += 1
        ip_snd = filtered(snd, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)

        if ip_snd is None:
            continue

        if snd_upper is None:
            # The first sending packet is always matched to handle cases where the receiver starts capturing before the sender
            while ip_rcv is None or ip_snd.id > ip_rcv.id:
                ts_rcv, rcv = next(rcv_reader)
                rcv_idx += 1
                ip_rcv = filtered(rcv, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)
            snd_lower = snd_upper = ip_snd.id
            arrival_time_utc = datetime.datetime.fromtimestamp(ts_snd, datetime.timezone.utc)
            arrival_time_ms = arrival_time_utc.strftime('%S.%f')[:-3]
            first_world_time = arrival_time_ms
            time2end = arrival_time_utc + datetime.timedelta(seconds=end_time)

        # prev_id = ip_snd.id
        # total_len = ip_snd.len
        # Handle packet aggregation (e.g., when the receiving packet exceeds MTU)
        # if prev_id == ip_rcv.id:
        #     prv_len = ip_rcv.len - MTU
        #     idx = 0
        #     while prv_len > 0:
        #         try:
        #             ts_snd, snd = next(snd_reader)
        #             snd_idx += 1
        #         except StopIteration:
        #             # IP assemble error
        #             print("Error for IP assemble!")
        #             break
        #         ip_snd = filtered(snd, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)
        #         if ip_snd is None:
        #             continue
        #         else:
        #             prv_len -= MTU
        #             idx += 1
        #             total_len += ip_snd.len
        # OOO_buffer[prev_id] = (ts_snd, total_len, snd_idx)

        # Update the upper bound of the sending packets
        while snd_upper != ip_snd.id:
            snd_upper += 1
            if snd_upper >= 65536:
                snd_upper = 0

            # Check for lost packets
            if abs(snd_upper - snd_lower) == 32768:
                if OOO_buffer[snd_lower]:
                    snd_rcv_lst.append(
                        (OOO_buffer[snd_lower][0], None, OOO_buffer[snd_lower][1])
                    )
                    loss_sum += 1
                    OOO_buffer[snd_lower] = None
                snd_lower += 1
                if snd_lower >= 65536:
                    snd_lower = 0

        # Match received packets with sent packets based on IPID
        while not rcv_end and (
            ip_rcv.id == snd_upper or
            ip_rcv.id == snd_lower or
            seq_lt(snd_lower, ip_rcv.id) and seq_lt(ip_rcv.id, snd_upper)):
            ooo_ts_snd = OOO_buffer[ip_rcv.id]

            if ooo_ts_snd is not None:
                snd_rcv_lst.append((ooo_ts_snd[0], ts_rcv, ip_rcv.len))
                OOO_buffer[ip_rcv.id] = None
            else:
                error_info = f"Error: received frame {rcv_idx} id {ip_rcv.id} not in the OOO buffer. Current snd_lower:{snd_lower} and snd_upper:{snd_upper}"
                raise Exception(error_info)

            # Update the lower bound of the sending packets
            while OOO_buffer[snd_lower] is None and snd_lower != snd_upper:
                snd_lower += 1
                if snd_lower >= 65536:
                    snd_lower = 0

            # Move to the next received packet
            while True:
                try:
                    ts_rcv, rcv = next(rcv_reader)
                    rcv_idx += 1
                except StopIteration:
                    rcv_end = True
                    break
                ip_rcv = filtered(rcv, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)
                if ip_rcv is not None:
                    rcv_filter_sum += 1
                    break

    snd_f.close()
    rcv_f.close()

    # Handle any remaining packets in the OOO buffer
    # for i in range(65536):
    #     if OOO_buffer[i] is not None:
    #         snd_rcv_lst.append(
    #             (OOO_buffer[i][0], None, OOO_buffer[i][1])
    #         )
    #         loss_sum += 1
    #         OOO_buffer[i] = None

    end = time.perf_counter()
    print('Match IPID Time:', end - start, 's')
    return snd_rcv_lst, first_world_time


def snd_rcv_stats(snd_rcv_lst, interval, t0):
    """
    Calculates statistics for sending and receiving packets.

    Parameters:
    - snd_rcv_lst: List of tuples containing (sending timestamp, receiving timestamp, IP layer length).
    - interval: The time interval for statistics calculation (in seconds).
    - t0: The starting timestamp for statistics calculation.

    Returns:
    - snd_rate_y: List of sending rates (in Bps).
    - delay_y: List of average delays (in milliseconds).
    - loss_y: List of packet loss rates.
    - rcv_rate_y: List of receiving rates (in Bps).
    """
    snd_rcv_lst.sort(key=lambda tup: tup[0])  # Sort by sending timestamp

    snd_rate_y = []  # Sending rate (Bps)
    delay_y = []     # Average delay (ms)
    loss_y = []      # Packet loss rate
    t_i = t0 + interval
    snd_bytes, delay_sum, loss_num, rcv_num = 0, 0, 0, 0

    for snd_ts, rcv_ts, length in snd_rcv_lst:
        while snd_ts > t_i:
            snd_rate_y.append(snd_bytes / interval)
            if rcv_num > 0:
                delay_y.append(1000 * delay_sum / rcv_num)
            else:
                if len(delay_y) == 0:
                    delay_y.append(0)
                else:
                    delay_y.append(delay_y[-1])

            if rcv_num + loss_num > 0:
                loss_y.append(loss_num / (rcv_num + loss_num))
            else:
                if len(loss_y) == 0:
                    loss_y.append(0)
                else:
                    loss_y.append(loss_y[-1])
            snd_bytes, delay_sum, loss_num, rcv_num = 0, 0, 0, 0
            t_i += interval

        snd_bytes += length
        if rcv_ts is None:
            loss_num += 1
        else:
            rcv_num += 1
            delay_sum += rcv_ts - snd_ts
            if rcv_ts < snd_ts:
                raise Exception("Received packet is earlier than sent packet!")

    rcv_lst = [(rcv_ts, length) 
               for _, rcv_ts, length in snd_rcv_lst if rcv_ts is not None]
    rcv_lst.sort(key=lambda tup: tup[0])

    rcv_rate_y = []  # Receiving rate (Bps)
    rcv_bytes = 0
    t_i = t0 + interval
    for rcv_ts, length in rcv_lst:
        while rcv_ts > t_i:
            rcv_rate_y.append(rcv_bytes / interval)
            rcv_bytes = 0
            t_i += interval
        rcv_bytes += length

    return snd_rate_y, delay_y, loss_y, rcv_rate_y


def per_packet_delay(snd_rcv_lst):
    """
    Calculates the delay for each packet.

    Parameters:
    - snd_rcv_lst: List of tuples containing (sending timestamp, receiving timestamp, IP layer length).

    Returns:
    - delay_y: List of delays (in milliseconds). -1 indicates a lost packet.
    """
    snd_rcv_lst.sort(key=lambda tup: tup[0])  # Sort by sending timestamp

    delay_y = []  # Delay (ms)
    for snd_ts, rcv_ts, length in snd_rcv_lst:
        if rcv_ts is not None:
            delay_y.append((rcv_ts - snd_ts) * 1000)
            if rcv_ts < snd_ts:
                print("Received packet is earlier than sent packet! ERROR!")
                exit(1)
        else:
            delay_y.append(-1)

    return delay_y


def calculate_average_throughput(rcv_csv_path, end_time, col_name='Length', round_len=2):
    """
    Calculates the average throughput from a CSV file.

    Parameters:
    - rcv_csv_path: Path to the CSV file containing packet data.
    - end_time: The duration for calculating throughput (in seconds).
    - col_name: The column name for packet length (default: 'Length').
    - round_len: The number of decimal places for the result (default: 2).

    Returns:
    - The average throughput (in Mbps).
    """
    total_throughput = 0

    with open(rcv_csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            length = int(row[col_name]) * 8  # Convert bytes to bits
            total_throughput += length

        total_throughput /= end_time * 1e6  # Convert to Mbps
    return round(total_throughput, round_len)


def calculate_interval_throughput_from_csv(csv_path, interval, start_time, duration, col_name='Length'):
    """
    Calculates the throughput for specified intervals from a CSV file.

    Parameters:
    - csv_path: Path to the CSV file containing packet data.
    - interval: The time interval for calculating throughput (in seconds).
    - start_time: The starting time for calculating throughput (in seconds).
    - duration: The duration for calculating throughput (in seconds).
    - col_name: The column name for packet length (default: 'Length').

    Returns:
    - interval_lst: List of tuples containing (interval start time, throughput in bps).
    """
    total_throughput = 0
    interval_throughput = 0
    current_time = start_time
    interval_lst = []

    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            time = float(row['Time'])
            if time < start_time:
                continue
            if time >= start_time + duration:
                break

            length = int(row[col_name]) * 8  # Convert bytes to bits
            total_throughput += length
            if time - current_time < interval:
                interval_throughput += length
            else:
                while time - current_time >= interval:
                    interval_lst.append((round(current_time, 3), interval_throughput / interval))
                    interval_throughput = 0
                    current_time += interval
                interval_throughput = length

        # Output the throughput for the last interval
        interval_lst.append((round(current_time, 3), interval_throughput / interval))

    return interval_lst


def calculate_interval_throughput_from_pcap(pcap_path, interval, duration, mode, L4_type, ip_lst, port_lst, len_filter_lower=LEN_FILTER_LOWER, len_filter_upper=LEN_FILTER_UPPER):
    """
    Calculates the throughput for specified intervals from a PCAP file.

    Parameters:
    - pcap_path: Path to the PCAP file containing packet data.
    - interval: The time interval for calculating throughput (in seconds).
    - duration: The duration for calculating throughput (in seconds).
    - mode: The mode of operation (see `filtered` function).
    - L4_type: The Layer 4 protocol type (see `filtered` function).
    - ip_lst: List of allowed (source, destination) IP pairs (see `filtered` function).
    - port_lst: List of allowed (source, destination) port pairs (see `filtered` function).
    - len_filter_lower: Lower bound for packet length filtering (optional).
    - len_filter_upper: Upper bound for packet length filtering (optional).

    Returns:
    - interval_lst: List of throughput values (in bps) for each interval.
    - first_world_time: The timestamp of the first packet.
    - last_world_time: The timestamp of the last packet.
    """
    interval_lst = []
    interval_throughput = 0
    packet_idx = 0
    first_world_time, last_world_time, interval_start_time = None, None, None

    pcap_file = open(pcap_path, 'rb')
    reader = dpkt.pcap.Reader(pcap_file)
    for timestamp, frame in reader:
        packet_time = float(timestamp)
        packet_idx += 1

        ip = filtered(frame, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)
        if ip is None:
            continue

        if first_world_time is None:
            first_world_time = interval_start_time = packet_time
        if packet_time - interval_start_time < interval:
            interval_throughput += ip.len
        else:
            while packet_time - interval_start_time >= interval:
                interval_lst.append(interval_throughput / interval)
                interval_throughput = 0
                interval_start_time += interval
            if interval_start_time - first_world_time >= duration:
                break
            interval_throughput = ip.len

    last_world_time = interval_start_time
    return interval_lst, first_world_time, last_world_time


def calculate_all_average_throughput_from_pcap(pcap_path, duration, mode, L4_type, ip_lst, port_lst, len_filter_lower=LEN_FILTER_LOWER, len_filter_upper=LEN_FILTER_UPPER):
    """
    Calculates the overall average throughput from a PCAP file.

    Parameters:
    - pcap_path: Path to the PCAP file containing packet data.
    - duration: The duration for calculating throughput (in seconds).
    - mode: The mode of operation (see `filtered` function).
    - L4_type: The Layer 4 protocol type (see `filtered` function).
    - ip_lst: List of allowed (source, destination) IP pairs (see `filtered` function).
    - port_lst: List of allowed (source, destination) port pairs (see `filtered` function).
    - len_filter_lower: Lower bound for packet length filtering (optional).
    - len_filter_upper: Upper bound for packet length filtering (optional).

    Returns:
    - The average throughput (in bps).
    """
    avg_throughput = 0
    pcap_file = open(pcap_path, 'rb')
    reader = dpkt.pcap.Reader(pcap_file)
    for _, frame in reader:
        ip = filtered(frame, mode, L4_type, ip_lst, port_lst, len_filter_lower, len_filter_upper)
        if ip is not None:
            avg_throughput += ip.len
    return avg_throughput / duration