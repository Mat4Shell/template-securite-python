from scapy.all import get_if_list, IFACES, get_if_addr, get_if_hwaddr
from typing import List, Dict, Optional
import platform


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def get_available_interfaces() -> List[str]:
    """
    Get list of available network interfaces

    Returns:
        List of interface names
    """
    try:
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []


def get_interface_details(iface: str) -> Dict[str, Optional[str]]:
    """
    Get detailed information about a network interface

    Args:
        iface: Interface name

    Returns:
        Dictionary with interface details (name, ip, mac, description)
    """
    details = {
        'name': iface,
        'ip': None,
        'mac': None,
        'description': None,
        'friendly_name': None
    }

    try:
        # Try to get IP address
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                details['ip'] = ip
        except:
            pass

        # Try to get MAC address
        try:
            mac = get_if_hwaddr(iface)
            if mac and mac != "00:00:00:00:00:00":
                details['mac'] = mac
        except:
            pass

        # Try to get description from IFACES
        try:
            iface_info = IFACES.dev_from_name(iface)
            if hasattr(iface_info, 'description') and iface_info.description:
                details['description'] = iface_info.description
            if hasattr(iface_info, 'name') and iface_info.name:
                details['friendly_name'] = iface_info.name
        except:
            pass

    except Exception as e:
        print(f"Warning: Could not get details for {iface}: {e}")

    return details


def format_interface_display(idx: int, iface: str, details: Dict[str, Optional[str]]) -> str:
    """
    Format interface information for display

    Args:
        idx: Interface index number
        iface: Interface name
        details: Interface details dictionary

    Returns:
        Formatted string for display
    """
    lines = []

    # Header with index
    if details['description']:
        # Use description as main title (e.g., "Intel(R) Wi-Fi 6 AX201")
        lines.append(f"[{idx}] {details['description']}")
    elif details['friendly_name']:
        lines.append(f"[{idx}] {details['friendly_name']}")
    else:
        # Fallback to raw name
        lines.append(f"[{idx}] {iface}")

    # IP Address (most important for user)
    if details['ip']:
        lines.append(f"    IP:  {details['ip']}")
    else:
        lines.append(f"    IP:  (No IP assigned)")

    # MAC Address
    if details['mac']:
        lines.append(f"    MAC: {details['mac']}")

    # Add a hint if interface seems inactive
    if not details['ip'] or details['ip'] == "0.0.0.0":
        lines.append(f"    Status: [INACTIVE - No IP]")

    return "\n".join(lines)


def display_interfaces() -> None:
    """
    Display all available network interfaces with details in a readable format
    """
    try:
        interfaces = get_available_interfaces()

        if not interfaces:
            print("\n[!] No network interfaces found!")
            return

        print("\n" + "=" * 70)
        print("AVAILABLE NETWORK INTERFACES")
        print("=" * 70)

        # Collect all interface details
        interface_data = []
        for iface in interfaces:
            details = get_interface_details(iface)
            interface_data.append((iface, details))

        # Sort: Active interfaces (with IP) first, then inactive
        interface_data.sort(key=lambda x: (x[1]['ip'] is None, x[0]))

        # Display formatted interfaces
        for idx, (iface, details) in enumerate(interface_data, 1):
            print(format_interface_display(idx, iface, details))
            print()  # Blank line between interfaces

        print("=" * 70)
        print("TIP: Interfaces with IP addresses are likely active")
        print("=" * 70)

    except Exception as e:
        print(f"Error displaying interfaces: {e}")


def choose_interface() -> str:
    """
    Return network interface based on user choice

    Returns:
        Selected interface name (empty string if cancelled or error)
    """
    try:
        interfaces = get_available_interfaces()

        if not interfaces:
            print("\n[!] No network interfaces found!")
            return ""

        # Display interfaces
        display_interfaces()

        # Collect interface details for reference
        interface_data = []
        for iface in interfaces:
            details = get_interface_details(iface)
            interface_data.append((iface, details))

        # Sort same way as display
        interface_data.sort(key=lambda x: (x[1]['ip'] is None, x[0]))

        # Ask user to choose
        while True:
            try:
                choice_input = input(f"\nSelect interface [1-{len(interfaces)}] (or 'q' to quit): ").strip()

                if choice_input.lower() == 'q':
                    print("Cancelled by user.")
                    return ""

                idx = int(choice_input)

                if 1 <= idx <= len(interfaces):
                    selected_iface, selected_details = interface_data[idx - 1]

                    # Show what was selected
                    print("\n" + "-" * 70)
                    print("Selected interface:")
                    print(format_interface_display(idx, selected_iface, selected_details))
                    print("-" * 70)

                    # Warn if interface has no IP
                    if not selected_details['ip'] or selected_details['ip'] == "0.0.0.0":
                        print("\n[!] WARNING: This interface has no IP address!")
                        print("[!] You may not capture any meaningful traffic on this interface.")
                        confirm = input("Continue anyway? (y/n): ").strip().lower()
                        if confirm != 'y':
                            continue

                    # Final confirmation
                    confirm = input("\nConfirm this interface? (y/n): ").strip().lower()
                    if confirm == 'y':
                        return selected_iface
                    else:
                        print("\nLet's try again...")
                        continue
                else:
                    print(f"[!] Please enter a number between 1 and {len(interfaces)}")

            except ValueError:
                print("[!] Invalid input. Please enter a number.")
            except KeyboardInterrupt:
                print("\n\nCancelled by user.")
                return ""

    except Exception as e:
        print(f"Error choosing interface: {e}")
        return ""