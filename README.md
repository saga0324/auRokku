# auRokku

auRokku is a command-line utility for compatible au feature phones. It communicates with the handset through a private USB service to inspect or change UIM lock, phone lock code, ICCID, and maintenance state.

## Features

- Display the phone serial number, service version, phone lock code, UIM lock state, and ICCID record.
- Read, clear, or write the UIM lock binding.
- Read or reset the phone lock code.
- Read the ICCID record.
- Change the maintenance bit.
- Run grouped basic or UIM lock queries.
- Produce human-readable or JSON output.

## Requirements

- Python 3.10 or newer
- `pyusb`
- A working libusb backend

```bash
python3 -m pip install pyusb
```

## Usage

Display the current device status:

```bash
python3 auRokku.py --op status
```

Read the UIM lock state:

```bash
python3 auRokku.py --op readuimlk
```

Read the ICCID record or phone lock code:

```bash
python3 auRokku.py --op readiccid
python3 auRokku.py --op readpin
```

Clear the UIM lock binding:

```bash
python3 auRokku.py --op clearlk
```

Write a four-byte UIM lock value:

```bash
python3 auRokku.py --op writelk --val 80e48ed2 --control 1
```

Reset the phone lock code to `1234`:

```bash
python3 auRokku.py --op resetpin
```

Change the maintenance bit:

```bash
python3 auRokku.py --op maintenance_bit --control 1
python3 auRokku.py --op maintenance_bit --control 0
```

Run a grouped read profile:

```bash
python3 auRokku.py --op batch --profile basic
python3 auRokku.py --op batch --profile uimlk
```

Exit the current service mode:

```bash
python3 auRokku.py --op exit
python3 auRokku.py --op exituimlk
```

Use `--json` for machine-readable output or `--verbose` to display USB traffic:

```bash
python3 auRokku.py --op status --json
python3 auRokku.py --op status --verbose
```

Use `--help` to display all available options.

## Device Selection

The default USB IDs are vendor `0482` and product `0a5c`. Override them when required:

```bash
python3 auRokku.py --op status --vid 0482 --pid 0a5c
```

auRokku normally reads the serial number from the USB descriptor. If it is unavailable, provide either the 11-character serial number or the raw Hex NV value:

```bash
python3 auRokku.py --op status --sn SKYKA077394
python3 auRokku.py --op status --sn 947307414B594B53
```

## Authentication Modes

In KYY06/KYY09/KYY10 need use Type 2 authentication!

Use `--type2` for phones that require base `52/53` authentication:

```bash
python3 auRokku.py --op status --type2
```

## Warning

The `status`, `readuimlk`, `readiccid`, `readpin`, and `batch` operations are intended for inspection. The `clearlk`, `writelk`, `resetpin`, and `maintenance_bit` operations will directly modify NVs.
