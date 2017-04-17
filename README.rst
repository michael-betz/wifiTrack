wifiTrack
=========

This project is all about doing geolocation in a sneaky way.

The ESP32's wifi and bluetooth peripherals allow to get a list of nearby access points and BLE beacons. This information is collected periodically and sent back home through open wifi access points. The ability of many public hotspots to carry out geniue DNS requests is exploited to relay back information to an internet server. The actual geolocation is carried out there, utilizing the Google or Mozilla geolocation APIs. 
