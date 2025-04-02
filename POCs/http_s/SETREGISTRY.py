import winreg
import json
import os


items_to_delete = []
items_to_set_back = []

config_json = None

DATA = 0
DELETE = 1
SET_BACK_TO = 2

PATH = 0
KEY = 1



json_path = "registry_items.json"


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

    print(f"{name} SET TO: {value}")

    winreg.CloseKey(key)

def delete_registry_value(root, path, name):
    try:
        key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)

        print(f"{name} DELETED")
    except FileNotFoundError:
        pass
        
def set_registry_dir_by_json(parent_key):
    global config_json, items_to_delete, items_to_set_back
    if config_json is None:
        return
        
    root = winreg.HKEY_CURRENT_USER
    path = parent_key


    for key in config_json[parent_key]:
        set_registry_value(root, path, key, config_json[parent_key][key][DATA])
        if config_json[parent_key][key][DELETE]:
            items_to_delete.append((path, key))
        else:
            items_to_set_back.append((path, key, config_json[parent_key][key][SET_BACK_TO]))
  

def revert_changes():
    global config_json, items_to_delete, items_to_set_back
    root = winreg.HKEY_CURRENT_USER
    for to_delete in items_to_delete:
        delete_registry_value(root, to_delete[PATH], to_delete[KEY])

    for to_set_back in items_to_set_back:
        set_registry_value(root, to_set_back[PATH], to_set_back[KEY], to_set_back[SET_BACK_TO])

def main():
    global config_json, items_to_delete, items_to_set_back
    config_json = json.load(open(json_path))
    
    for path in config_json.keys():
        print("*"*30)
        print(path)
        set_registry_dir_by_json(path)
        print("*"*30)


    input("Press enter to revert changes...")

    revert_changes()
    
    input("Press Enter To redo...")
    os.system('cls')
    items_to_delete = []
    items_to_set_back = []

    config_json = None
    main()

    


if __name__ == "__main__":
    main()
