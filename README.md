# BATSClient
A python toolbox for request data from [BATS](https://bats.earth.sinica.edu.tw/).

## Install
Download the zip file of this package and extract it.

Install conda to create virtual environment for python.
[https://docs.conda.io/en/latest/miniconda.html](https://docs.conda.io/en/latest/miniconda.html)
```shell
# create virtual environments
conda create -n BATSClient python=3 pip
conda activate BATSClient

# install dependencies
pip install -r requirement.txt
```

### get_waveforms
```python
>>> from client import Client
>>> client = Client('BATS')
>>> client.set_credentials('username', 'password')
>>> from obspy import UTCDateTime
>>> t = UTCDateTime("2008-04-16T00:00:00.000")
>>> st = client.get_waveforms("CHGB", "*", t, t + 60 * 60, 'ms')
>>> print(st)
6 Trace(s) in Stream:
TW.CHGB..BHE | 2008-04-16T00:00:00.019538Z - 2008-04-16T00:59:59.969538Z | 20.0 Hz, 72000 samples
TW.CHGB..BHN | 2008-04-16T00:00:00.019538Z - 2008-04-16T00:59:59.969538Z | 20.0 Hz, 72000 samples
TW.CHGB..BHZ | 2008-04-16T00:00:00.019538Z - 2008-04-16T00:59:59.969538Z | 20.0 Hz, 72000 samples
TW.CHGB..BLE | 2008-04-16T00:00:00.019538Z - 2008-04-16T00:59:59.969538Z | 20.0 Hz, 72000 samples
TW.CHGB..BLN | 2008-04-16T00:00:00.019538Z - 2008-04-16T00:59:59.969538Z | 20.0 Hz, 72000 samples
TW.CHGB..BLZ | 2008-04-16T00:00:00.019538Z - 2008-04-16T00:59:59.969538Z | 20.0 Hz, 72000 samples
>>>st.plot(outfile='Trace.png')
>>>
```
