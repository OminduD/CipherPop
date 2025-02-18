import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESSIV, AESGCMSIV, AESCCM, AESOCB3
from cryptography.exceptions import UnsupportedAlgorithm, InvalidTag
from datetime import datetime
import getpass
import pyzipper
import tempfile
import json
from pathlib import Path
import mimetypes
from rich.console import Console
from rich.panel import Panel

now = datetime.now()
Time = now.strftime("%Y-%m-%d %H.%M.%S")
console = Console()
def keysave(secret, folderName):
    with tempfile.NamedTemporaryFile(delete=False, mode ='w', newline='', encoding="utf-8" ) as temp_file:
        temp_file.write(secret)
        temp_file_path = temp_file.name
        running = True
        while running:
            try:
                console.print("\n[green][+] Creating encryption key...[/green]")    
                console.print("[yellow]A [bold]password[/bold] for a key file is a secret phrase or code used to protect and access the key file, which contains cryptographic keys. The password ensures that only authorized users can unlock and use the keys stored in the file, adding an extra layer of security. Without the correct password, the key file remains inaccessible, safeguarding sensitive data. [/yellow]")
                console.print("[bold yellow]Enter your password: [/bold yellow]")
                password1 = getpass.getpass(">>> ")
                console.print("[bold yellow]Confirm your password:  [/bold yellow]")
                password2 = getpass.getpass(">>> ")
            except KeyboardInterrupt:
                console.print("\n[red][-] Keyboard Interrupt![/red]")
                console.print("\n[green][+] Exiting...[/green]")
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass
                except Exception:
                    pass
                except PermissionError:
                    pass
                exit()
            except EOFError:
                console.print("\n[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z)[/red]")
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass
                except Exception:
                    pass
                except PermissionError:
                    pass
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")
            if password1 == password2 :
                if password1:
                    running = False
                else:
                    console.print("[red][-] Password can't be empty![/red]")
            else:
                console.print("[red][-] Password does not match![/red]")
    try:   
        with pyzipper.AESZipFile(f"{folderName}\\key{Time}.zip", 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password1.encode())
            zf.write(temp_file_path, arcname= "key.txt")
            console.print(f"[green][+] Key saved successfully at: {f'{folderName}\\key{Time}.zip'}'[/green]")
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")
    finally:
        os.remove(temp_file_path)

def encripted_file_save(encrypt_data, encrypt_filename):
    user_folder = Path.home()
    Mainfolder = "CipherPop"
    folder_Path = user_folder / Mainfolder
    if  folder_Path.exists() and folder_Path.is_dir():
        console.print(f"[green][+] Main Folder: {folder_Path} already exists[/green]")
    else:
        try:
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        except PermissionError:
            console.print(f"[red][-] PermissionError: You don't have permission to create {folder_Path}[/red]")
            current_folder = Path.cwd()
            folder_Path = f"{current_folder}\\CipherPop"
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            current_folder = Path.cwd()
            folder_Path = f"{current_folder}\\CipherPop"
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        
    global encrypt_folderName
    encrypt_folderName = f"{folder_Path}\\Encrypt [{Time}]"
    try:
        os.mkdir(encrypt_folderName)
        console.print(f"[green][+] Encrypt Folder: {encrypt_folderName} created[/green]")
    except:
        pass

    try:
        with open(f"{encrypt_folderName}\\{encrypt_filename}(encoded).enc", "wb") as f:
            f.write(encrypt_data)
            encrypt_ReadMe(encrypt_folderName)
            console.print(f"[green][+] Encrypted Data saved successfully[/green]")
    except OSError: 
        console.print(f"[red][-] OSError: An error occurred while accessing {encrypt_folderName}[/red]")
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")
def decrypt_file_save(decripted_data):
    user_folder = Path.home()
    Mainfolder = "CipherPop"
    folder_Path = user_folder / Mainfolder
    if  folder_Path.exists() and folder_Path.is_dir():
        console.print(f"[green][+] Main Folder: {folder_Path} already exists[/green]")
    else:
        try:
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        except PermissionError:
            console.print(f"[red][-] PermissionError: You don't have permission to create {folder_Path}[/red]")
            current_folder = Path.cwd()
            folder_Path = f"{current_folder}\\CipherPop"
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            current_folder = Path.cwd()
            folder_Path = f"{current_folder}\\CipherPop"
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
    global encrypt_folderName
    decrypt_folderName = f"{folder_Path}\\Decrypt [{Time}]"
    try:
        os.mkdir(decrypt_folderName)
        console.print(f"[green][+] Decrypt Folder: {decrypt_folderName} created[/green]")
    except:
        pass

    try:
        with open(f"{decrypt_folderName}\\{decrepit_name}", "wb") as f:
            f.write(decripted_data)
            decrypt_ReadMe()
            console.print(f"[green][+] Decrypted data Saved as {decrepit_type}[/green]")
    except OSError:  
        console.print(f"[red][-] OSError: An error occurred while accessing {decrypt_folderName}[/red]")
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")



def encripted_file_open():
    running = True
    while running:
        try:
            running1 = True
            while running1:
                try:
                    console.print("[bold yellow]Enter the file path:  [/bold yellow]")
                    file_path = input(">>> ")
                    running1 = False
                except KeyboardInterrupt:
                    console.print("\n[red][-] Keyboard Interrupt![/red]")
                    console.print("\n[green][+] Exiting...[/green]")
                    console.exit()
                except EOFError:
                    console.print("\n[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z)[/red]")

                except Exception as e:
                    console.print(f"[red][-] Error: {e}[/red]")
        except FileNotFoundError as e:
            console.print(f"[red][-] FileNotFoundError: {e}[/red]")
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    global encripted_data
                    encripted_data = f.read()
                    console.print(f"[green][+] Encrypted data loaded successfully[/green]")
                    running = False
            except PermissionError:
                console.print(f"[red][-] PermissionError: You don't have permission to access {file_path}[/red]")
            except IsADirectoryError:
                console.print(f"[red][-] IsADirectoryError: {file_path} is a directory[/red]")
            except IOError:
                console.print(f"[red][-] IOError: An error occurred while accessing {file_path}[/red]")
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")
        else:
            console.print(f"[red][-] File not found in {file_path}. Please try again![/red]")
        
    

def secret_file_open():
    running = True
    while running:
        
        running1 = True
        while running1:
                try:
                    console.print("[bold yellow]Enter the path to the key file: [/bold yellow]")
                    secret_file_path = input(">>> ")
                    running1 = False
                except KeyboardInterrupt:
                    console.print("[red][-] Keyboard Interrupt![/red]")
                    console.print("[green][+] Exiting...[/green]")
                    console.exit()
                except EOFError:
                    console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z)[/red]")
                except Exception as e:
                    console.print(f"[red][-] Error: {e}[/red]")
        
        if os.path.exists(secret_file_path):
            try:
                with open(secret_file_path, "r") as f:
                    global secret
                    secret = json.load(f)
                    console.print("[green][+] Key file loaded successfully[/green]")
                    running = False
            except json.JSONDecodeError:
                console.print(f"[red][-] JSONDecodeError: Invalid JSON in {secret_file_path}[/red]")
            except PermissionError:
                console.print(f"[red][-] PermissionError: You don't have permission to access {secret_file_path}[/red]")
            except IsADirectoryError:
                console.print(f"[red][-] IsADirectoryError: {secret_file_path} is a directory[/red]")
            except IOError:
                console.print(f"[red][-] IOError: An error occurred while accessing {secret_file_path}[/red]")
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")

        else:
            console.print(f"[red][-] File not found in {secret_file_path}. Please try again![/red]")
    
    global decrepit_key, decrepit_nonce, decrepit_aad, decrepit_type, decrepit_name
    decrepit_key = bytes.fromhex(secret["key"])
    decrepit_nonce = bytes.fromhex(secret["nonce"])
    decrepit_aad = secret["aad"].encode("utf-8")
    decrepit_type = secret["type"]
    decrepit_name= secret["name"]

def Encryption_engine():
    running = True
    while running:
        try:
            console.print("[bold yellow]Input your data [yellow](Input Text phrase you want to encrypt)[/yellow]: [/bold yellow]")
            data = input(">>> ")
            running = False
        except OverflowError as e:
            console.print(f"[red][-] OverflowError: {e}[/red]")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("\n[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")
        except Exception as e:
            console.print(f"[red][-] Error: {e} \nTry again[/red]")
    running = True
    while running:
        try:
            console.print("[yellow] [bold]AAD[/bold] (Additional Authenticated Data) is extra information (like headers or metadata) that isn't encrypted but is protected against tampering. It's included in the authentication process to ensure its integrity alongside the encrypted data. If the AAD is altered, the system detects it and rejects the data.[/yellow]")
            console.print("[bold yellow]Input your AAD: [/bold yellow]")
            aad = input(">>> ")
            running = False
        except OverflowError as e:
            console.print(f"[red][-] OverflowError: {e} \nTry again[/red]")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("\n[green][+] Exiting...[/green]")
            console.exit()
        except EOFError:
            console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")
        except Exception as e:
            console.print(f"[red][-] Error: {e} \nTry again[/red]")

    data = data.encode("utf-8")
    aad = aad.encode("utf-8")
    nonce = os.urandom(12)
     
    
    try:
        console.print("[green][+] Try with Chacha20 first[/green]")
        key = ChaCha20Poly1305.generate_key()
        encrypt_key = ChaCha20Poly1305(key)
        console.print("[green][+] Encoded by ChaCha20Poly1305 Algorithm[/green]")
    except UnsupportedAlgorithm as e:
        console.print(f"[red][-] Unsupported Algorithm: {e}[/red]")
        console.print("[green][+] Retry with AES-GSM Algorithm[/green]")
        try:
            key = AESGCM.generate_key(bit_length=256)
            encrypt_key = AESGCM(key)
            console.print("[green][+] Encoded by AES-GCM Algorithm[/green]")
        except UnsupportedAlgorithm as e:
            console.print(f"[red][-] Unsupported Algorithm: {e}[/red]")
            console.print("[green][+] Retry with AES-SIV Algorithm[/green]")
            try:
                key = AESSIV.generate_key(bit_length=256)
                encrypt_key = AESSIV(key)
                console.console.print("[green][+] Encoded by AES-SIV Algorithm[/green]")
            except UnsupportedAlgorithm as e:
                console.print(f"[red][-] Unsupported Algorithm: {e}[/red]")
                console.print("[red][-] Failed to encode data[/red]")
    encrypt_filename = "encrypt_file"
    secret = json.dumps({
        "aad": aad.decode("utf-8"),
        "nonce": nonce.hex(),
        "key": key.hex(),
        "type": "Text/plain",
        "name": "decrypt_file.txt",
        

    })

    encrypt_data = encrypt_key.encrypt(nonce, data, aad)
    encripted_file_save(encrypt_data, encrypt_filename)
    keysave(secret, encrypt_folderName)
    

def Decryption_engine():
    encripted_file_open()
    for attempt in range(3):
        secret_file_open()
        console.print("[green][+] Decryption trying with ChaCha algorithm[/green]")
        try:
            chacha = ChaCha20Poly1305(decrepit_key)
            decripted_data = chacha.decrypt(decrepit_nonce, encripted_data, decrepit_aad)
            console.print(f"[green][+] Decrypted data Success with ChaCha algorithm[/green]")
            break
    
        except ValueError as e:
            console.print(f"[red][-] ValueError: {e}[/red]")
            console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
        except InvalidTag or UnsupportedAlgorithm:
            console.print(f"[red][-] Decryption fail with Chacha alogrithm[/red]")
            console.print("[green][+] Decryption trying with AES-GSM algorithm[/green]")
            try:
                aesgcm = AESGCM(decrepit_key)
                decripted_data = aesgcm.decrypt(decrepit_nonce, encripted_data, decrepit_aad)
                console.print(f"[green][+] Decrypted data Success with AES-GSM algorithm[/green]")
                break
            except ValueError as e:
                console.print(f"[red][-] ValueError: {e}")
                console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
            except InvalidTag or UnsupportedAlgorithm:
                console.print(f"[red][-] Decryption fail with AES-GSM alogrithm[/red]")
                console.print("[green][+] Decryption trying with AES-SIV algorithm[/green]")
                try:
                    aes_siv = AESSIV(decrepit_key)
                    decripted_data = aes_siv.decrypt(decrepit_nonce, encripted_data, decrepit_aad)
                    console.print(f"[green][+] Decrypted data Success with AES-SIV algorithm[/green]")
                    break
                except ValueError as e:
                    console.print(f"[red][-] ValueError: {e}[/red]")
                    console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                except InvalidTag or UnsupportedAlgorithm:
                    console.print(f"[red][-] Decryption fail with AES-SIV alogrithm[/red]")
                    console.print("[green][+] Decryption trying with AES-GSMIV algorithm[/green]")
                    try:
                        aesgcmsiv = AESGCMSIV(decrepit_key)
                        decripted_data = aesgcmsiv.decrypt(decrepit_nonce, encripted_data, decrepit_aad)
                        console.print(f"[green][+] Decrypted data Success with AES-GSMIV algorithm[/green]")
                        break
                    except ValueError as e:
                        console.print(f"[red][-] ValueError: {e}[/red]")
                        console.print(f"[ref][-] Wrong secret file! {2-attempt} attempts left![/red]")
                    except InvalidTag or UnsupportedAlgorithm:
                        console.print(f"[red][-] Decryption fail with AES-GSMIV alogrithm[/red]")
                        console.print("[green][+] Decryption trying with AESOCB3 algorithm[/green]")
                        try:
                            aesocb = AESOCB3(decrepit_key)
                            decripted_data = aesocb.decrypt(decrepit_nonce, encripted_data, decrepit_aad)
                            console.print(f"[green][+] Decryption success with AES-OCB3 alogrithm[/green]")
                            break
                        except ValueError as e:
                            console.print(f"[red][-] ValueError: {e}[/red]")
                            console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                        except InvalidTag or UnsupportedAlgorithm:
                            console.print(f"[red][-] Decryption fail with AES-OCB3 alogrithm[/red]")
                            console.print("[green][+] Decryption trying with AES-CCM algorithm[/green]")
                            try:
                                aesccm = AESCCM(decrepit_key)
                                decripted_data = aesccm.decrypt(decrepit_nonce, encripted_data, decrepit_aad)
                                console.print(f"[green][+] Decryption success with AES-CCM alogrithm[/green]")
                                break
                            except ValueError as e:
                                console.print(f"[red][-] ValueError: {e}[/red]")
                                console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                            except InvalidTag or UnsupportedAlgorithm:
                                console.print(f"[red][-] Decryption fail with AES-CCM alogrithm[/red]")
                                console.print(f"[red][-] Failed to decrypt data or Wrong secret file! {2-attempt} attempts left![/red] ")        
    else:
        console.print("[bold red][-] Too many invalid attempts Exiting program...[/bold red]")
        exit()
    decrypt_file_save(decripted_data)
def encrypt_ReadMe(encrypt_folderName):
    content = '''
   _____  _         _                  _____              
  / ____|(_)       | |                |  __ \             
 | |      _  _ __  | |__    ___  _ __ | |__) |___   _ __  
 | |     | || '_ \ | '_ \  / _ \| '__||  ___// _ \ | '_ \ 
 | |____ | || |_) || | | ||  __/| |   | |   | (_) || |_) |
  \_____||_|| .__/ |_| |_| \___||_|   |_|    \___/ | .__/ 
            | |                                    | |    
            |_|                                    |_|    

                                                    Created by OminduD


How to Decrypt a File
    -Unzip the key file
    -Run the CipherPop 
    -Follow the on screen instructions
    -Enter the path of the encrypted file 
    -Enter the path of the key file
    -Press Enter

Thank you for using this Tool!

    '''
    with open(f"{encrypt_folderName}\\README.md", 'w') as f:
        f.write(content)
        f.close()

def decrypt_ReadMe():
    content = '''
   _____  _         _                  _____              
  / ____|(_)       | |                |  __ \             
 | |      _  _ __  | |__    ___  _ __ | |__) |___   _ __  
 | |     | || '_ \ | '_ \  / _ \| '__||  ___// _ \ | '_ \ 
 | |____ | || |_) || | | ||  __/| |   | |   | (_) || |_) |
  \_____||_|| .__/ |_| |_| \___||_|   |_|    \___/ | .__/ 
            | |                                    | |    
            |_|                                    |_|    
   
                                                    Created by OminduD

Thank you for using this Tool!
    
'''
    with open('README.md', 'w') as f:
        f.write(content) 
        f.close()

def Encrypt_file_Engine():
    running = True
    while running:
        running1 = True
        while running1:
                try:
                    console.print("[yellow] Enter your File Path to Encrypt[/yellow]")
                    file_path = input(">>> ")
                    running1 = False
                except KeyboardInterrupt:
                    console.print("[red][-] Keyboard Interrupt![/red]")
                    console.print("[green][+] Exiting...[/green]")
                    exit()
                except EOFError:
                    console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")

                except Exception as e:
                    console.print(f"[red][-] Error: {e} \nTry again[/red]")
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                    mime_type, _ = mimetypes.guess_type(file_path)
                    console.print(f"[green][+] File successfully loaded. File Type: {mime_type}[/green]")
                    running = False
            except FileNotFoundError:
                console.print(f"[red][-] File not found at {file_path}. Please try again![/red]")
                exit()
            except PermissionError:
                console.print(f"[red][-] Permission denied to access {file_path}. Please try again![/red]")
            except OverflowError as e:
                console.print(f"[red][-] OverflowError: {e} \nTry again[/red]")
            except Exception as e:
                console.print(f"[red][-] Error: {e} \nTry again[/red]")
                exit()
        else:
            console.print(f"[red][-] {file_path} is not a valid file path. Please try again![/red]")    
    running = True

    while running:
        try:
            console.print("[yellow] [bold]AAD[/bold] (Additional Authenticated Data) is extra information (like headers or metadata) that isn't encrypted but is protected against tampering. It's included in the authentication process to ensure its integrity alongside the encrypted data. If the AAD is altered, the system detects it and rejects the data.[/yellow]")
            console.print("[bold yellow]Input your AAD: [/bold yellow]")
            aad = input(">>> ")
            running = False
        except OverflowError as e:
            console.print(f"[red][-] OverflowError: {e} \nTry again[/red]")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")
        except Exception as e:
            console.print(f"[red][-] Error: {e} \nTry again[/red]")
    

    aad = aad.encode("utf-8")
    nonce = os.urandom(12)
     
    
    try:
        console.print("[green][+] Try with Chacha20 first[/green]")
        key = ChaCha20Poly1305.generate_key()
        encrypt_key = ChaCha20Poly1305(key)
        console.print("[green][+] Encoded by ChaCha20Poly1305 Algorithm[/green]")
    except UnsupportedAlgorithm as e:
        console.print(f"[red][-] Unsupported Algorithm: {e}[/red]")
        console.print("[green][+] Retry with AES-GSM Algorithm[/green]")
        try:
            key = AESGCM.generate_key(bit_length=256)
            encrypt_key = AESGCM(key)
            console.print("[green][+] Encoded by AES-GCM Algorithm[/green]")
        except UnsupportedAlgorithm as e:
            console.print(f"[red][-] Unsupported Algorithm: {e}[/red]")
            console.print("[green][+] Retry with AES-SIV Algorithm[/green]")
            try:
                key = AESSIV.generate_key(bit_length=256)
                encrypt_key = AESSIV(key)
                console.print("[green][+] Encoded by AES-SIV Algorithm[/green]")
            except UnsupportedAlgorithm as e:
                console.print(f"[red][-] Unsupported Algorithm: {e}[/red]")
                console.print("[red][-] Failed to encode data[/red]")
    encrypt_filename = Path(file_path).name
    secret = json.dumps({
        "aad": aad.decode("utf-8"),
        "nonce": nonce.hex(),
        "key": key.hex(),
        "type": mime_type,
        "name": encrypt_filename

    })

    encrypt_data = encrypt_key.encrypt(nonce, data, aad)
    encripted_file_save(encrypt_data, encrypt_filename)
    keysave(secret, encrypt_folderName)

def manual_description_engine():
    encripted_file_open()
    for attempt in range(3):
        try:
            console.print("[bold yellow] Input your key: [/bold yellow]")
            manual_key = input(">>> ")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            console.print(f"[red][-] Wrong key type  {2-attempt} attempts left![/red]")
        except Exception as e:
            console.print(f"[red][-] Wrong key type {2-attempt} attempts left![/red]")

        try:
            console.print("[bold yellow]Input your AAD(Additional Authenticated Data):")
            manual_aad = input(">>> ")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            console.print(f"[red][-] Wrong aad type {2-attempt} attempts left![/red]")
        except Exception as e:
            console.print(f"[red][-] Wrong aad type {2-attempt} attempts left![/red]")
        try:
            console.print("[bold yellow]Input your nonce[yellow](A [bold]nonce[/bold](number used once) is a unique, random value used in cryptography to ensure encryption results are different each time, even for the same data, preventing replay attacks)[/yellow]:[/bold yellow]")
            manual_nonce = input(">>> ")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("\n[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            console.print(f"[red][-] Wrong nonce type  {2-attempt} attempts left![/red]")
        except Exception as e:
            console.print(f"[red][-] Wrong nonce type {2-attempt} attempts left![/red]")
        manual_excisions = ".txt"
        try:
            console.print("[bold yellow]Input File Extension:[/bold yellow]")
            manual_excisions = input(">>> ")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            pass
        except Exception as e:
            pass
        manual_name = "decrypt_file"
        try:
            console.print(f"[bold yellow]Input File Name:[/bold yellow]")
            manual_excisions = input(">>> ")
        except KeyboardInterrupt:
            console.print("[red][-] Keyboard Interrupt![/red]")
            console.print("[green][+] Exiting...[/green]")
            exit()
        except EOFError:
            pass
        except Exception as e:
            pass
        manual_key = bytes.fromhex(manual_key)
        manual_nonce= bytes.fromhex(manual_nonce)
        manual_aad = manual_aad.encode("utf-8")
        console.print("[green][+] Decryption trying with ChaCha algorithm[/green]")
        try:
            chacha = ChaCha20Poly1305(manual_key)
            decripted_data = chacha.decrypt(manual_nonce, encripted_data, manual_aad)
            console.print(f"[green][+] Decrypted data Success with ChaCha algorithm[/green]")
            break
    
        except ValueError as e:
            console.print(f"[red][-] ValueError: {e}[/red]")
            console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
        except InvalidTag or UnsupportedAlgorithm:
            console.print(f"[red][-] Decryption fail with Chacha alogrithm[/red]")
            console.print("[green][+] Decryption trying with AES-GSM algorithm[/green]")
            try:
                aesgcm = AESGCM(decrepit_key)
                decripted_data = aesgcm.decrypt(manual_nonce, encripted_data, manual_aad)
                console.print(f"[green][+] Decrypted data Success with AES-GSM algorithm[q][/green]")
                break
            except ValueError as e:
                console.print(f"[red][-] ValueError: {e}[/red]")
                console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
            except InvalidTag or UnsupportedAlgorithm:
                console.print(f"[red][-] Decryption fail with AES-GSM alogrithm[/red]")
                console.print("[green][+] Decryption trying with AES-SIV algorithm,/green")
                try:
                    aes_siv = AESSIV(decrepit_key)
                    decripted_data = aes_siv.decrypt(manual_nonce, encripted_data, manual_aad)
                    console.print(f"[green][+] Decrypted data Success with AES-SIV algorithm[/green]")
                    break
                except ValueError as e:
                    console.print(f"[red][-] ValueError: {e}[/red]")
                    console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                except InvalidTag or UnsupportedAlgorithm:
                    console.print(f"[red][-] Decryption fail with AES-SIV alogrithm[/red]")
                    console.print("[green][+] Decryption trying with AES-GSMIV algorithm[/green]")
                    try:
                        aesgcmsiv = AESGCMSIV(decrepit_key)
                        decripted_data = aesgcmsiv.decrypt(manual_nonce, encripted_data, manual_aad)
                        console.print(f"[green][+] Decrypted data Success with AES-GSMIV algorithm[/green]")
                        break
                    except ValueError as e:
                        console.print(f"[red][-] ValueError: {e}[/red]")
                        console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                    except InvalidTag or UnsupportedAlgorithm:
                        console.print(f"[red][-] Decryption fail with AES-GSMIV alogrithm[/red]")
                        console.print("[green][+] Decryption trying with AESOCB3 algorithm[/green]")
                        try:
                            aesocb = AESOCB3(decrepit_key)
                            decripted_data = aesocb.decrypt(manual_nonce, encripted_data, manual_aad)
                            console.print(f"[green][+] Decryption success with AES-OCB3 alogrithm[/green]")
                            break
                        except ValueError as e:
                            console.print(f"[red][-] ValueError: {e}[/red]")
                            console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                        except InvalidTag or UnsupportedAlgorithm:
                            console.print(f"[red][-] Decryption fail with AES-OCB3 alogrithm[/red]")
                            console.print("[green][+] Decryption trying with AES-CCM algorithm[/green]")
                            try:
                                aesccm = AESCCM(decrepit_key)
                                decripted_data = aesccm.decrypt(manual_nonce, encripted_data, manual_aad)
                                console.print(f"[green[[+] Decryption success with AES-CCM alogrithm[/green]")
                                break
                            except ValueError as e:
                                console.print(f"[red][-] ValueError: {e}[/red]")
                                console.print(f"[red][-] Wrong secret file! {2-attempt} attempts left![/red]")
                            except InvalidTag or UnsupportedAlgorithm:
                                console.print(f"[red][-] Decryption fail with AES-CCM alogrithm[/red]")
                                console.print(f"[red][-] Failed to decrypt data or Wrong secret file! {2-attempt} attempts left![/red] ")        
    else:
        console.print("[bold red][-] Too many invalid attempts Exiting program...[/bpld red]")
        exit()
    user_folder = Path.home()
    Mainfolder = "CipherPop"
    folder_Path = user_folder / Mainfolder
    if  folder_Path.exists() and folder_Path.is_dir():
        console.print(f"[green][+] Main Folder: {folder_Path} already exists[/green]")
    else:
        try:
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        except PermissionError:
            console.print(f"[red][-] PermissionError: You don't have permission to create {folder_Path}[/red]")
            current_folder = Path.cwd()
            folder_Path = f"{current_folder}\\Encrypt Tool"
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            current_folder = Path.cwd()
            folder_Path = f"{current_folder}\\Encrypt Tool"
            folder_Path.mkdir(parents=True, exist_ok=True)
            console.print(f"[green][+] Main Folder: {folder_Path} created[/green]")
    decrypt_folderName = f"{folder_Path}\\Decrypt [{Time}]"
    try:
        os.mkdir(decrypt_folderName)
        console.print(f"[green][+] Decrypt Folder: {decrypt_folderName} created[/green]")
    except:
        pass

    try:
        with open(f"{decrypt_folderName}\\{manual_name}{manual_excisions}", "wb") as f:
            f.write(decripted_data)
            console.print(f"[green][+] Decrypted data Saved as {decrepit_type}[/green]")
    except OSError: 
        console.print(f"[red][-] OSError: An error occurred while accessing {decrypt_folderName}[/red]")
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")

        

            
console.print(''' [rgb(205,53,255)]


                                     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██████╗  ██████╗ ██████╗ 
                                    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
                                    ██║     ██║██████╔╝███████║█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝
                                    ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██╔═══╝ 
                                    ╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║     ╚██████╔╝██║     
                                     ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝    
                                                                                        



[/rgb(205,53,255)]
[yellow]
This tool is a custom cryptographic encryption and decryption utility that uses an authenticated encryption algorithm to ensure data confidentiality and integrity. It allows users to securely encrypt and decrypt messages or files with a secret key.
Features

        [bold]Authenticated Encryption:[/bold] Ensures both confidentiality and data integrity.

        [bold]Secure Key Management:[/bold] Uses a secret key for encryption and decryption.

        [bold]Easy-to-Use Interface:[/bold] Simple command-line or GUI-based interaction.

        [bold]Fast and Efficient:[/bold] Optimized for performance without compromising security.
[/yellow]
      ''')
def mainmenu():
    console.print(''' [yellow]
            [italic]1. Encrypt Tool[/italic]
            [italic]2. Decryption Tool[/italic]
              

If you want to [bold]Exit[/bold] type [bold]exit[/bold] or press [bold]Ctrl+C[/bold]
Type [bold]about[/bold] for [bold]More Information[/bold]
Choose an option and follow the prompts to start using our cryptography tool. Remember to keep your secret key safe and secure.              
[/yellow]''')
def about():
    console.print(Panel('''
                                       
[cyan]Our cryptography tool is designed to provide strong security for sensitive data through advanced encryption techniques. It ensures data integrity, prevents unauthorized access, and offers an easy-to-use interface for encrypting and decrypting messages or files. Whether you're securing personal information or handling confidential business data, this tool helps you keep your information safe from cyber threats.

[bold italic bright_magenta]Features[/bold italic bright_magenta]

    [bold]Authenticated Encryption:[/bold] Ensures both confidentiality and data integrity.

    [bold]Secure Key Management:[/bold] Uses a secret key for encryption and decryption.

    [bold]Easy-to-Use Interface:[/bold] Simple command-line or GUI-based interaction.

    [bold]Fast and Efficient:[/bold] Optimized for performance without compromising security.


[bold italic bright_magenta]Requirements[/bold italic bright_magenta]

To use this tool, ensure you have the following installed:

    -Python 3.8+

    -Required libraries (install via pip install -r requirements.txt if applicable)
                        
                        
[bold italic bright_magenta]Security Considerations[/bold italic bright_magenta]

    [bold]Key Management:[/bold] Ensure your secret key is stored securely and not shared with unauthorized users.

    [bold]Data Integrity:[/bold] Always verify decrypted data to ensure it hasn’t been tampered with.
                        

[bold italic bright_magenta]Contribution[/bold italic bright_magenta]

Feel free to submit issues or pull requests to enhance the tool.
                        
[blue]
                                 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██████╗  ██████╗ ██████╗ 
                                ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
                                ██║     ██║██████╔╝███████║█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝
                                ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██╔═══╝ 
                                ╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║     ╚██████╔╝██║     
                                 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝ 
                                                                                    Created by OminduD[/blue]

[/cyan]''', title="[bold blue]ABOUT[/bold blue]", border_style="rgb(39,0,169)"))
mainmenu()

while True:
    running = True
    while running:
        running1 = True
        while running1:
            try:
                choose = input(">>> ")
                running1 = False
            except KeyboardInterrupt:
                console.print("[green][+] Exiting...[/green]")
                exit()
            except EOFError:
                console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")
            except Exception as e:
                console.print(f"[red][-] Error: {e} \nTry again[/red]")
        if choose == "1":
            console.print('''[yellow]
                [italic]1. Encrypt File[/italic]
                [italic]2. Encrypt Text[/italic]
    If you want to [bold]Exit[/bold] type [bold]exit[/bold] or press [bold]Ctrl+C[/bold]
    Type [bold]about[/bold] for [bold]More Information[/bold]
    Type [bold]back[/bold] for [bold]Main menu[/bold]
    Choose an option and follow the prompts to start encrypting your data.  
            [/yellow]''')
            running2 = True
            while running2:
                try:
                    choose2 = input(">>> ")
                    running2 = False
                except KeyboardInterrupt:
                    console.print("[green][+] Exiting...[/green]")
                    exit()
                except EOFError:
                    console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")
                except Exception as e:
                    console.print(f"[red][-] Error: {e} \nTry again[/red]")
            if choose2 == "1":
                    Encrypt_file_Engine()
                    mainmenu()
            elif choose2 == "2":
                    Encryption_engine()
                    mainmenu()
            elif choose2.lower() == "back":
                console.print("[green][+] Returning to Main menu...[/green]")
                mainmenu()
                running = False
            elif choose2.lower == "about":
                about()
            elif choose2.lower() == "exit":
                console.print("[green][+] Exiting...[/green]")
                exit()
            else:
                console.print("[red][-] Invalid option. Try again.[/red]")
        elif choose == "2":
            console.print('''[yellow]
                [italic]1. Decrypt with Key file[/italic]
                [italic]2. Mannuel Decrypt[/italic]
    If you want to [bold]Exit[/bold] type [bold]exit[/bold] or press [bold]Ctrl+C[/bold]
    Type [bold]about[/bold] for more information
    Type [bold]back[/bold] for Main menu
    Choose an option and follow the prompts to start decrypting your data.  
            [/yellow]''')
            running3 = True
            while running3:
                try:
                    choose3 = input(">>> ")
                    running3 = False
                except KeyboardInterrupt:
                    console.print("[green][+] Exiting...[/green]")
                    exit()
                except EOFError:
                    console.print("[red][-] Input cancelled via EOF(Ctrl+D/Ctrl+Z) \nTry again[/red]")
                except Exception as e:
                    console.print(f"[red][-] Error: {e} \nTry again[/red]")
            if choose3 == "1":
                Decryption_engine()
                mainmenu()
            elif choose3 == "2":
                manual_description_engine()
                mainmenu()
            elif choose3.lower() == "back":
                console.print("[green][+] Returning to Main menu...[/green]")
                mainmenu()
                running = False
            elif choose3.lower() == "about":
                about()
            elif choose3.lower() == "exit":
                console.print("[green][+] Exiting...[/green]")
                exit()
            
        elif choose.lower() == "about":
                    about()
        elif choose.lower() == "exit":
                console.print("[green][+] Exiting...[/green]")
                exit()
        else:
            console.print("[red][-] Invalid option. Try again.[/red]")
            