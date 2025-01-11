from scapy.all import sniff

def packet_handler(packet):
    """Callback function to process captured packets."""
    print(packet.summary())

def main():
    print("Sniffing started... Press Ctrl+C to stop.")
    try:
        # Sniff packets on all interfaces and process with `packet_handler`
        sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\nSniffing stopped.")

if __name__ == "__main__":
    main()
