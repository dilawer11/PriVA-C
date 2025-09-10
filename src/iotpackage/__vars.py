from types import SimpleNamespace

simpleFeatureGroups = {
    'Total Packets': {
        'suffix': '_totalpkts',
        'description': 'input and output total packet counts'
    },
    'Total Bytes': {
        'suffix': '_totalbytes',
        'description': 'incoming and outgoing total packet size'
    },
    'Unique Packet Length': {
        'suffix': '_uniquelen',
        'description': 'incoming and outgoing unique packet length distribution features'
    },
    'Packet Length': {
        'suffix': '_len',
        'description': 'incoming and outgoing all packet length distribution features'
    },
    'Total Percentage': {
        'suffix': '_percentage',
        'description': 'incoming and outgoing total packet ratio/percentage'
    },
    'External Counts': {
        'suffix': '_extcount',
        'description': 'external ip, hostname, port based counts',
    },
    'Inter-Burst Delays': {
        'suffix': '_interburstdelay',
        'description': 'distribution features of delay between end of one burst and start of another',
    },
    'Burst Length': {
        'suffix': '_burstbytes',
        'description': 'distribution features of the bytes in one burst',
    },
    'Burst Packet Count': {
        'suffix': '_burstnumpkts',
        'description': 'distribution features of the count of packets in one burst',
    },
    'Burst Time': {
        'suffix': '_bursttime',
        'description': 'distribution features of how long a burst lasts'
    },
    'Inter-Packet Delay': {
        'suffix': '_interpktdelay',
        'description': 'distribution features of delay between two packets',
    },
    'Flow Length': {
        'suffix': '_flowbytes',
        'description': 'distribution features of the bytes in one flow',
    },
    'Flow Packet Count': {
        'suffix': '_flownumpkts',
        'description': 'distribution features of the count of packets in one flow',
    },
    'Flow Time': {
        'suffix': '_flowtime',
        'description': 'distribution features of how long a flow lasts'
    },
}
dictFeatureGroups = {
    'External Port': {
        'suffix': '_dict_extport',
        'description': 'External ports contacted and their counts in a dict-like feature'
    },
    'IP': {
        'suffix': '_dict_ip',
        'description': 'IPs contacted and their counts in a dict-like feature'
    },
    'Hostname': {
        'suffix': '_dict_hostname',
        'description': 'Hostnames contacted and their counts in a dict-like feature'
    },
    'Packet Lengths': {
        'suffix': '_dict_packetlens',
        'description': 'Packet lengths and their counts in outgoing and incoming traffic in a dict-like feature'
    },
    'Ping Pong Pairs': {
        'suffix': '_dict_pingpong',
        'description': 'Ping pong pairs. individual packet req reply lengths and their counts in a dict-like feature'
    },
    'Req Reply Packet Lengths': {
        'suffix': '_dict_reqreplylens',
        'description': 'Request reply pair lens over multiple packets and their counts in a dict-like feature',
    },
    'Protocols': {
        'suffix': '_dict_protocols',
        'description': 'Protocols and their counts in a dict-like-feature',
    }
}

CSV_cols = {
    'SrcIP' : 'ip.src',
    'DstIP' : 'ip.dst',
    'Protocol' : '_ws.col.Protocol',
    'tcpSrcPort' : 'tcp.srcport',
    'tcpDstPort' : 'tcp.dstport',
    'udpSrcPort' : 'udp.srcport',
    'udpDstPort' : 'udp.dstport',
    'Proto' : 'ip.proto',
    'Frame' : 'frame.number',
    'Time' : 'frame.time_epoch',
    'tcpACK' : 'tcp.flags.ack',
    'tcpSYN' : 'tcp.flags.syn',
    'tcpRST' : 'tcp.flags.reset',
    'tcpFIN' : 'tcp.flags.fin',
    'tcpPSH' : 'tcp.flags.push',
    'tcpURG' : 'tcp.flags.urg',
    'Length' : 'frame.len'
}


defaultVals = {
    "windows": {
        "new_flow_win_width": 0,
        "inactive_flow_timeout": 15,
        "active_flow_timeout": 60,
        "hostname_method": "both",
    },
    "feature_selector": {
        "n_all": 0,
        "n_tcp": 100,
        "n_udp": 50,
        "n_proto": 10,
        "simple_groups": "all",
        "dict_groups": "all",
        "simple_features": [],
        "dict_features": [],
        "one_hot_encode": True,
    },
    "model_training": {
        "model_name": "RandomForestClassifier",
        "plot_cm": True,
        "errors": True,
        "label_col": "label",
        "features": True,
        "test_size": 0.2,
        "max_samples": None,
        "metric_average": "macro",
        "per_label_metrics": False,
        "print_metrics": True,
        "remove_threshold": 10,
    }
}