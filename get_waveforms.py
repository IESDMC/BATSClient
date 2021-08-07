from client import Client
# Client options
# IES : http://tecws1.earth.sinica.edu.tw/IESWS
# BATS: http://tecws1.earth.sinica.edu.tw/BATSWS
client = Client('BATS', debug=False)
client.set_credentials('username', 'password')
from obspy import UTCDateTime
t = UTCDateTime("2008-04-16T00:00:00.000")
st = client.get_waveforms("CHGB", "BH?", t, t + 60 * 60, 'ms')
print(st)
st.plot(outfile='Trace.png')