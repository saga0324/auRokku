# auRokku

auRokku is a command-line utility for compatible au feature phones. It communicates with the handset through a private USB service to inspect or change UIM lock, phone lock code, ICCID, and maintenance state.

## Features

- Display the phone serial number, service version, phone lock code, UIM lock state, and ICCID record.
- Read, clear, or write the UIM lock binding.
- Read or reset the phone lock code.
- Read the ICCID record.
- Change the maintenance bit.
- Run grouped basic or UIM lock queries.
- Enumerate USB configurations, interfaces, alternate settings, endpoints, and bulk endpoint pairs.
- Run bounded SERI or SCDP liveness probes on an explicitly selected USB channel.
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
python3 auRokku.py --vid 0482 --pid 0a5c --op status
```

Read the UIM lock state:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op readuimlk
```

Read the ICCID record or phone lock code:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op readiccid
python3 auRokku.py --vid 0482 --pid 0a5c --op readpin
```

Clear the UIM lock binding:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op clearlk
```

Write a four-byte UIM lock value:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op writelk --val 80e48ed2 --control 1
```

Reset the phone lock code to `1234`:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op resetpin
```

Change the maintenance bit:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op maintenance_bit --control 1
python3 auRokku.py --vid 0482 --pid 0a5c --op maintenance_bit --control 0
```

Run a grouped read profile:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op batch --profile basic
python3 auRokku.py --vid 0482 --pid 0a5c --op batch --profile uimlk
```

Exit the current service mode:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op exit
python3 auRokku.py --vid 0482 --pid 0a5c --op exituimlk
```

Use `--json` for machine-readable output or `--verbose` to display USB traffic:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op status --json
python3 auRokku.py --vid 0482 --pid 0a5c --op status --verbose
```

Use `--help` to display all available options.

## USB Probe

Start with the passive descriptor probe. It does not require a serial number, claim an interface, or send protocol traffic:

```bash
python3 auRokku.py --vid 04dd --pid 934a --op probe --json
```

The result lists every USB configuration, interface, alternate setting, endpoint, and candidate bulk OUT/IN pair. Use the reported values instead of assuming that the default interface and endpoints are correct.

Run a bounded SERI probe on one selected channel:

```bash
python3 auRokku.py \
  --vid 04dd --pid 934a \
  --interface 2 --ep-out 04 --ep-in 84 \
  --op probe --probe-kind seri --probe-timeout 1.0 --verbose
```

The SERI probe sends `1c 05` and succeeds only when the response begins with the same bytes. After a matching response, auRokku sends `d8` to leave the service on non-Sony devices. It does not send authentication, UIM lock, PIN, or maintenance commands.

Run a bounded SCDP synchronization probe:

```bash
python3 auRokku.py \
  --vid 04dd --pid 934a \
  --interface 2 --ep-out 04 --ep-in 84 \
  --op probe --probe-kind scdp --probe-timeout 1.0 --json
```

The SCDP probe sends only `8e` and reports the raw bounded response. Keep SERI and SCDP probes separate; do not run both protocol families on the same channel without identifying the interface first.

`--interface` is a decimal interface number. `--ep-out` and `--ep-in` are hexadecimal endpoint addresses. OUT endpoints must have bit 7 clear, and IN endpoints must have bit 7 set. The endpoint options can also override the defaults for normal auRokku operations.

## Device Selection

Both `--vid` and `--pid` are required hexadecimal USB IDs. Replace the example values with your device IDs:

```bash
python3 auRokku.py --op status --vid 0482 --pid 0a5c
```

auRokku normally reads the serial number from the USB descriptor. If it is unavailable, provide either the 11-character serial number or the raw hexadecimal Type2Auth value:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op status --sn SKYKA077394
python3 auRokku.py --vid 0482 --pid 0a5c --op status --sn 947307414B594B53
```

## Authentication Modes

KYY06, KYY09, and KYY10 require Type 2 authentication.

Use `--type2` for phones that require base `52/53` authentication:

```bash
python3 auRokku.py --vid 0482 --pid 0a5c --op status --type2
```

## Warning

The `status`, `readuimlk`, `readiccid`, `readpin`, and `batch` operations are intended for inspection. The `clearlk`, `writelk`, `resetpin`, and `maintenance_bit` operations will directly modify NVs.

The default `probe` mode only reads USB descriptors. The `seri` and `scdp` probe kinds transmit the packets documented above. Use descriptor output to select the correct interface and endpoint pair before running an active probe. A response proves only that the selected USB channel reacted; it does not prove that other auRokku operations are compatible with that handset.
