class IEEE80211Types:
    MANAGEMENT = 0x00
    CONTROL = 0x04
    DATA = 0x08


ieee80211_type_to_str = {
    IEEE80211Types.MANAGEMENT: 'Management',
    IEEE80211Types.CONTROL: 'Control',
    IEEE80211Types.DATA: 'Data',
}


class IEEE80211ManagementSubtypes:
    # for TYPE_MGT
    ASSOC_REQ=0x00
    ASSOC_RESP=0x10
    REASSOC_REQ=0x20
    REASSOC_RESP=0x30
    PROBE_REQ=0x40
    PROBE_RESP=0x50
    BEACON=0x80
    ATIM=0x90
    DISASSOC=0xa0
    AUTH=0xb0
    DEAUTH=0xc0
    ACTION=0xd0
    ACTION_NOACK=0xe0	#/* 11n */


ieee80211_management_subtype_to_str = {
    IEEE80211ManagementSubtypes.ASSOC_REQ: 'Assoc request',
    IEEE80211ManagementSubtypes.ASSOC_RESP: 'Assoc response',
    IEEE80211ManagementSubtypes.REASSOC_REQ: 'Reassoc request',
    IEEE80211ManagementSubtypes.REASSOC_RESP: 'Reassoc response',
    IEEE80211ManagementSubtypes.PROBE_REQ: 'Probe request',
    IEEE80211ManagementSubtypes.PROBE_RESP: 'Probe response',
    IEEE80211ManagementSubtypes.BEACON: 'Beacon',
    IEEE80211ManagementSubtypes.ATIM: 'Atim',
    IEEE80211ManagementSubtypes.DISASSOC: 'Disassoc',
    IEEE80211ManagementSubtypes.AUTH: 'Auth',
    IEEE80211ManagementSubtypes.DEAUTH: 'Deauth',
    IEEE80211ManagementSubtypes.ACTION: 'Action',
    IEEE80211ManagementSubtypes.ACTION_NOACK: 'Action NOACK',
}


class IEEE80211ControlSubtypes:
    # for TYPE_CTL
    WRAPPER=0x70	#/* 11n */
    BAR=0x80
    BA=0x90
    PS_POLL=0xa0
    RTS=0xb0
    CTS=0xc0
    ACK=0xd0
    CF_END=0xe0
    CF_END_ACK=0xf0


ieee80211_control_subtype_to_str = {
    IEEE80211ControlSubtypes.WRAPPER: 'Wrapper',
    IEEE80211ControlSubtypes.BAR: 'Bar',
    IEEE80211ControlSubtypes.BA: 'Ba',
    IEEE80211ControlSubtypes.PS_POLL: 'PS poll',
    IEEE80211ControlSubtypes.RTS: 'RTS',
    IEEE80211ControlSubtypes.CTS: 'CTS',
    IEEE80211ControlSubtypes.ACK: 'ACK',
    IEEE80211ControlSubtypes.CF_END: 'CF end',
    IEEE80211ControlSubtypes.CF_END_ACK: 'CF end ack',
}


class IEEE80211DataSubtypes:
    # for TYPE_DATA (bit combination)
    DATA=0x00
    CF_ACK=0x10
    CF_POLL=0x20
    CF_ACPL=0x30
    NODATA=0x40
    CFACK=0x50
    CFPOLL=0x60
    CF_ACK_CF_ACK=0x70
    QOS=0x80

ieee80211_data_subtype_to_str = {
    IEEE80211DataSubtypes.DATA: 'Data',
    IEEE80211DataSubtypes.CF_ACK: 'CF ACK',
    IEEE80211DataSubtypes.CF_POLL: 'CF Poll',
    IEEE80211DataSubtypes.CF_ACPL: 'CF ACPL',
    IEEE80211DataSubtypes.NODATA: 'No data',
    IEEE80211DataSubtypes.CFACK: 'CF ACK',
    IEEE80211DataSubtypes.CFPOLL: 'CF POLL',
    IEEE80211DataSubtypes.CF_ACK_CF_ACK: 'CF ACK CF ACK',
    IEEE80211DataSubtypes.QOS: 'QOS',
}


ieee80211_subtype_to_str = {
    IEEE80211Types.MANAGEMENT: ieee80211_management_subtype_to_str,
    IEEE80211Types.CONTROL: ieee80211_control_subtype_to_str,
    IEEE80211Types.DATA: ieee80211_data_subtype_to_str,
}
