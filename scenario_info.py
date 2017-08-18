'''
Returns the pcap duration (in seconds) given the scenario number
Note that this is given in more detail in infected_hosts.txt
'''
def get_pcap_duration(scenario):
    if scenario == 6:
        return 7713
    if scenario == 7:
        return 1252
    if scenario == 9:
        return 18500
    if scenario == 10:
        return 17000
    if scenario == 11:
        return 936
    if scenario == 12:
        return 4400
    if scenario == 13:
        return 58824

'''
Returns the botnet_nodes dictionary (where botnet IP addresses are keys and 
the time they started are their values) given the scenario number.
Note that this is given in more detail in infected_hosts.txt
'''
def get_botnet_nodes(scenario):
    if scenario == 6:
        return {"147.32.84.165": 1313482127}
    if scenario == 7:
        return {"147.32.84.165": 1313495767}
    if scenario == 9:
        return {"147.32.84.165": 1313583848, "147.32.84.191": 1313585000, \
                "147.32.84.192": 1313585300, "147.32.84.193": 1313585685, \
                "147.32.84.204": 1313585767, "147.32.84.205": 1313585878, \
                "147.32.84.206": 1313586042, "147.32.84.207": 1313586116, \
                "147.32.84.208": 1313586193, "147.32.84.209": 1313586294}
    if scenario == 10:
        return {"147.32.84.165": 1313658370, "147.32.84.191": 1313658392, \
                "147.32.84.192": 1313658341, "147.32.84.193": 1313658412, \
                "147.32.84.204": 1313658313, "147.32.84.205": 1313658435, \
                "147.32.84.206": 1313658286, "147.32.84.207": 1313658260, \
                "147.32.84.208": 1313658232, "147.32.84.209": 1313658185}
    if scenario == 11:
        return {"147.32.84.165": 1313675308, "147.32.84.191": 1313675308, \
                "147.32.84.192": 1313675308}
    if scenario == 12:
        return {"147.32.84.165": 1313743359, "147.32.84.191": 1313743638, \
                "147.32.84.192": 1313743825}
    if scenario == 13:
        return {"147.32.84.165": 1313421481}

'''
Returns the time that the capture started given the scenario number
'''
def get_capture_start_time(scenario):
    if scenario == 6: # Starts at 10:01:58 CEST
        # approx 7 minutes before first infected botnet host
        return 1313481718
    if scenario == 7: # Starts at 13:51:25 CEST
        # approx 5 minutes before first infected botnet host
        return 1313495485
    if scenario == 9: # Starts at 14:24:08 CEST
        # approx 143 minutes before first infected botnet host
        return 1313575261
    if scenario == 10: # Starts at 10:19:02 CEST
        # approx 44 minutes before first infected botnet host
        return 1313655542
    if scenario == 11: # Starts at 15:39:41 CEST
        # approx 9 minutes before first infected botnet host
        return 1313674802
    if scenario == 12: # Starts at 10:32:08 CEST
        # approx 15 minutes before first infected botnet host
        return 1313742728
    if scenario == 13: # Starts at 17:14:41 CEST
        # approx 3 minutes before first infected botnet host
        return 1313421281
