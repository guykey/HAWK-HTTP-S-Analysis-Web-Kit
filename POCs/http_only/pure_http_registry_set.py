import winreg

def set_registry_value(root, path, name, value):
    try:
        # Open the key if it exists, else create it
        key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        key = winreg.CreateKey(root, path)

    # Set the registry value
    if type(value) is str:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    if type(value) is int:
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
    winreg.CloseKey(key)

def delete_registry_value(root, path, name):
    try:
        key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass

def main():
    root = winreg.HKEY_CURRENT_USER
    path = R"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

    # Define the registry items
    registry_Set = [
        ("ProxyEnable", 0x1),
        ("ProxyOverride", "<-loopback>"),
        ("ProxyServer", "http=127.0.0.1:8581")
    ]
    registry_delete = [
        "ProxyOverride", "ProxyServer"
    ]

    # Set registry values
    for name, value in registry_Set:
        set_registry_value(root, path, name, value)
        print(f"Set {name} to {value}")

    input("Press enter to revert changes...")

    # Delete registry values
    for name in registry_delete:
        delete_registry_value(root, path, name)
        print(f"Deleted {name}")

    set_registry_value(root, path, "ProxyEnable", 0x0)


if __name__ == "__main__":
    main()