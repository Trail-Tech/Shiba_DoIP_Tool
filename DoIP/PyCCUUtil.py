import socket
import sys
import binascii
import PyUDS
import time
import platform
import os


class PyUDS:
    ###UDS DEFINITIONS###

    ################################################################################
    ##### DIAGNOSTIC_SESSION_CONTROL_REQUEST(DSC)###################################
    ################################################################################
    DIAGNOSTIC_SESSION_CONTROL_REQUEST = DSC = '10'
    ################################################################################
    # DSC sub-function 0x00 : ISOSAE Reserved ######################################
    # <0x10><sub-function> #########################################################
    DEFAULT_SESSION = DS = '01'
    PROGRAMMING_SESSION = PRGS = '02'
    EXTENDED_DIAGNOSTIC_SESSION = EXTDS = '03'
    SAFETY_SYSTEM_DIAGNOSTIC_SESSION = SSDS = '04'
    #DSC sub-function 0x05-0x3F : ISOSAE Reserved
    #DSC sub-function 0x40-0x5F : vehicle manufacturer specifc
    #DSC sub-function 0x60-0x7E : system supplier specifc
    #DSC sub-function 0x7F : ISOSAE Reserved
    ################################################################################
    # DSC Positive Response Message/Code (PRM/PRC) #################################
    # <0x50><sub-function><not supported at Faraday> ###############################
    DIAGNOSTIC_SESSION_CONTROL_RESPONSE = DSCPR = '50'


    ################################################################################
    ##### CONTROL_DTC_SETTING (CDS) ################################################
    ################################################################################
    DIAGNOSTIC_DTC_SETTING_REQUEST = DCTS = '85'
    ################################################################################
    # DSC sub-function 0x00 : ISOSAE Reserved ######################################
    # <0x10><sub-function> #########################################################
    DTC_OFF = DTCOFF = '82'
    ################################################################################
    # DTC Positive Response Message/Code (PRM/PRC) #################################
    # <0x50><sub-function><not supported at Faraday> ###############################
    DIAGNOSTIC_DTC_SETTING_RESPONSE = DSCPR = 'C5'


    ################################################################################
    ##### Security Access (SA) ################################################
    ################################################################################
    DIAGNOSTIC_SECURITY_ACCESS_REQUEST = DSAREQ = '27'
    ################################################################################
    REQUEST_SEED = SARS = '03'
    SEND_KEY = SASC = '04'
    ################################################################################
    # DTC Positive Response Message/Code (PRM/PRC) #################################
    # <0x50><sub-function><not supported at Faraday> ###############################
    DIAGNOSTIC_SECURITY_ACCESS_RESPONSE = DSARSP = '67'


    ################################################################################
    ##### ECURESET(ER) #############################################################
    ################################################################################
    ECU_RESET = ER = '11'
    ################################################################################
    # ECU_RESET sub-function 0x00 : ISOSAE Reserved ################################
    HARD_RESET = HR = '01'
    KEY_OFF_ON_RESET = KOFFONR = '02'
    SOFT_RESET = SR = '03'
    ENABLE_RAPID_POWER_SHUTDOWN = ERPSD = '04'
    DISABLE_RAPID_POWER_SHUTDOWN = DRPSD = '05'
    #ECU_RESET sub-function 0x06-0x3F : ISOSAE Reserved
    #ECU_RESET sub-function 0x40-0x5F : ISOSAE Reserved
    #ECU_RESET sub-function 0x60-0x7E : System Supplier Specific
    #ECU_RESET sub-function 0x7F : ISOSAE Reserved
    ################################################################################
    # ER Positive Response Message/Code (PRM/PRC) ##################################
    # <0x51><sub-function><power down time -- present on ERPSD> ####################
    ECU_RESET_RESPONSE = ERPR = '51'


    ################################################################################
    ##### SECURITY ACCESS SERVICE(SA) ##################################################
    ################################################################################
    SECURITY_ACCESS_SERVICE = SA = '27'
    # <0x27>,<data record (odd for requestSeed, even for sendKey)>,<optional: security key>
    # SECURITY ACCESS SERVICE: REQUEST_SEED : <0x01|0x03|0x05|0x07-0x7D>
    # SECURITY ACCESS SERVICE: SEND_KEY: <0x02|0x04|0x06|0x08-0x7F>
    ################################################################################
    # SA Positive Response Message/Code (PRM/PRC) ##################################
    SECURITY_ACCESS_RESPONSE = SAPR = '67'


    ################################################################################
    ###COMMUNICATION_CONTROL_SERVICE (CC) <0x28><sub-function = [control type]><communication type>
    ################################################################################
    COMMUNICATION_CONTROL_SERVICE = CC = '28'
    ################################################################################
    ##CC Sub-functions
    ENABLE_RX_TX = ERXTX = '00'
    ENABLE_RX_DISABLE_TX = ERXDTX = '01'
    DISABLE_RX_ENABLE_TX = DRXETX = '02'
    DISABLE_RX_TX = DRXTX = '03'
    ENABLE_RX_DISABLE_TX_WITH_ENHANCED_ADDR_INFO = ERXDTXWEAI = '04'
    ENABLE_RX_TX_WITH_ENHANCED_ADDR_INFO = ERXTXWEAI = '05'
    ##CC sub-function 0x06-0x3F : ISOSAE Reserved
    ##CC sub-function 0x40-0x5F : Vehicle Manufacturer Specific
    ##CC sub-function 0x60-0x7E : System Supplier Specific 
    ##CC sub-function 0x7F : ISOSAE Reserved 
    ################################################################################
    ###CC communication type bit 0-3 (lower nibble)
    ###CC communication type bit 0-1 encoding 0x0: ISOSAE Reserved 
    NORMAL_COMMUNICATION_MESSAGES = NCM = '01'
    NETWORK_MANAGEMENT_COMMUNICATION_MESSAGES = NWMCM = '02'
    NETWORK_MANAGEMENT_COMMUNICATION_MESSAGES_NORMAL_COMMUNICATION_MESSAGES = NWMCM_NCM = '03'
    ################################################################################
    ###CC communication type bit 2-3 : ISOSAE Reserved -- Keep it 0x0 -- See above that it is kept 0x0
    ################################################################################
    ###CC subnet number bit 4-7 (upper nibble) -- Sets the setting for the optional subnet number. 
    DISABLE_OR_ENABLE_SPECIFIED_COMMUNICATION_TYPE = DISENSCT = '0'
    DISABLE_OR_ENABLE_SPECIFIC_SUBNET_ID_BY_SUBNET_NUMBER = DISENSSIVSN = '1' 
    #User should reset as needed. The above is defaulted to 1
    DISABLE_OR_ENABLE_NETWORK_WHICH_REQUEST_IS_RECEIVED_ON_NODE = 'F'
    #CC PRM <0x68><sub-function >
    COMMUNICATION_CONTROL_RESPONSE = CCPR = '68'


    #TESTER PRESENT <0x3E><Sub-function>#
    TESTER_PRESENT = TP = '3E'
    #Subfunctions 
    ZERO_SUB_FUNCTION = ZSUBF = '00'
    #0x01-0x7F ISOSAE Reserved 
    #PRM <7E><Sub-fucntion>
    TESTER_PRESENT_RESPONSE = TPPR ='7E'



    #REQUEST_DOWNLOAD0x34. <0x34><data format ID><address and legnth format ID><memory address><memory size>
    REQUEST_DOWNLOAD = RD = '34'
    DATA_FORMAT_ID = DFI_00 = "00" #00 is default, else vehicle manufacturer specific, no compression, no encryption
    ADDRESS_AND_LENGTH_FORMAT_ID = ALFID = '44' #44 ff default. 4 bytes for address, 4 bytes for memory size
    ##Memory address and memory size length specified by ALFID

    #TRANSFER_DATA0x36 <TD (0x34)><Block sequence counter(block index)><data>
    TRANSFER_DATA = TD = '36'

    #REQUEST_TRANSFER_EXIT (0x37)
    REQUEST_TRANSFER_EXIT = RTE = '37'


    #READ_DATA_BY_IDENTIFIER0x22##
    #DIDS: 0x00-0xFF
    #USE: 0x22<DID1>..<DIDn>
    READ_DATA_BY_IDENTIFIER = RDBI = '22'




    #WRITE_DATA_BY_IDENTIFIER0x2E##
    #DIDS: 0x00-0xFF
    #USE:0x22<DID><DataRecord>
    WRITE_DATA_BY_IDENTIFIER = WDBI = '2E'



    ### Routine Control 0x31 ####
    ROUTINE_CONTROL = RC = '31'
    START_ROUTINE = STR = '01'
    STOP_ROUTINE = STPR = '02'
    REQUEST_ROUTINE_RESULTS = RRR = '03'
    #all else isosae reserved

    #FF Supported Routines 
    ERASE_MEMORY = RC_EM = 'FF00'
    CHECK_MEMORY = RC_CM = '0202'
    CHECK_PROGRAMMING_DEPENDENCIES = RC_CPD = 'FF01' # might be deprecated
    REQUEST_COMPONENT_HASH_VALUE = RC_RCHV = 'FF02' #might be deprecated
    APPLICATION_AUTHORIZATION = RC_AA = 'FF03'




    #NEGATIVE RESPONSE MESSAGE/CODE (NRM/NRC)
    SUB_FUNCTION_NOT_SUPPORT = SFNS = '12'
    INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = IMLOIF = '13'
    CONDITIONS_NOT_CORRECT = CNC = '22'
    REQUEST_SEQUENCE_ERROR = RSE = '24'
    REQUEST_OUT_OF_RANGE = ROOR = '31'
    SECURITY_ACCESS_DENIED = SAD = '33'
    INVALID_KEY = IK = '35'
    EXCEEDED_NUMBER_OF_ATTEMPS = ENOA = '36'
    REQUIRED_TIME_DELAY_NOT_EXPIRED = RTDNE = '37'
    GENERAL_PROGRAMMING_FAILURE = GPF = '72'


    MEMORY_OPERATION_PENDING = MOPNDNG = '7F3178'
    TRANSFER_OPERATION_PENDING = TOPNDNG = '7F3678'



    #COMMON DIDs
    DID_PROGRAMMING_ATTEMPT_COUNTER = DID_PATTCTR = 'F110'
    DID_WRITE_FINGERPRINT 			= DID_WRFPRNT = 'F15A'
    DID_READ_FINGERPRINT			= DID_REFPRNT = 'F15B'
    DID_BOOT_SW_ID					= DID_BOOTSID = 'F180'
    DID_APP_CAL_SW_ID				= DID_APCASID = 'F181'
    DID_ACTIVE_DIAGNOSTIC_SESSION	= DID_ADIASES = 'F186'
    DID_ECU_SW_NUMBER				= DID_ECUSWNO = 'F188'
    DID_VIN_ID						= DID_VINIDNO = 'F190'	
    DID_APPLICATION_FLASH_FILE_NAME = DID_AFFN    = 'F111'



















# import argparse

# DoIP Header Structure : <protocol version><inverse protocol version><payload type><payloadlength><payload>
# Payload format : <local ecu address> <optional: target ecu addres> <optional message ><ASRBISO><ASRBOEM>

PROTOCOL_VERSION = DOIP_PV = '02'
INVERSE_PROTOCOL_VERSION = DOIP_IPV = 'FD'

# Payload type definitions#
DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE = DOIP_NARP = '0000'
DOIP_VEHICLE_ID_REQUEST = '0001'
DOIP_VEHICLE_ID_REQUEST_W_EID = '0002'
DOIP_VEHICLE_ID_REQUEST_W_VIN = '0003'
DOIP_VEHICLE_ANNOUNCEMENT_ID_RESPONSE = '0004'
# DOIP_ROUTING_ACTIVATION_REQUEST : <0005><sourceaddress><activation type><00000000>
DOIP_ROUTING_ACTIVATION_REQUEST = DOIP_RAR = '0005'
# Activation Type
DEFAULT_ACTIVATION = '00'
WWH_OBD_ACTIVATION = '01'
# 0x02-0xDF ISOSAE Reserved
CENTRAL_SECURITY_ACTIVATION = 'E0'
# 0xE1-0xFF OEM Specific
ACTIVATION_SPACE_RESERVED_BY_ISO = ASRBISO = '00000000'
# the code above is mandatory but has no use at the moment. ISOSAE Reserved
ACTIVATION_SPACE_RESERVED_BY_OEM = ASRBOEM = 'ffffffff'

DOIP_ROUTING_ACTIVATION_RESPONSE = '0006'
DOIP_ALIVE_CHECK_REQUEST = '0007'
DOIP_ALIVE_CHECK_RESPONSE = '0008'
# 0x009-0x4000: Reserved by ISO13400
DOIP_ENTITY_STATUS_REQUEST = '4001'
DOIP_ENTITY_STATUS_RESPONSE = '4002'
DOIP_DIAGNOSTIC_POWER_MODE_INFO_REQUEST = '4003'
DOIP_DIAGNOSTIC_POWER_MODE_INFO_RESPONSE = '4004'
# 0x4005-0x8000 Reserved by ISO13400
DOIP_DIAGNOSTIC_MESSAGE = DOIP_UDS = '8001'
DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE = '8002'
DOIP_DIAGNOSTIC_NEGATIVE_ACKNOWLEDGE = '8003'
# 0x8004-0xEFFF Reserved by ISO13400
# 0xF000-0xFFFF Reserved for manufacturer-specific use


payloadTypeDescription = {
    int(DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE): "Generic negative response",
    int(DOIP_VEHICLE_ID_REQUEST): "Vehicle ID request",
    int(DOIP_VEHICLE_ID_REQUEST_W_EID): "Vehicle ID request with EID",
    int(DOIP_VEHICLE_ID_REQUEST_W_VIN): "Vehicle ID request with VIN",
    int(DOIP_VEHICLE_ANNOUNCEMENT_ID_RESPONSE): "Vehicle announcement ID response",
    int(DOIP_ROUTING_ACTIVATION_REQUEST): "Routing activation request",
    int(DOIP_ROUTING_ACTIVATION_RESPONSE): "Routing activation response",
    int(DOIP_ALIVE_CHECK_REQUEST): "Alive check request",
    int(DOIP_ALIVE_CHECK_RESPONSE): "Alive check response",
    int(DOIP_ENTITY_STATUS_REQUEST): "Entity status request",
    int(DOIP_ENTITY_STATUS_RESPONSE): "Entity status response",
    int(DOIP_DIAGNOSTIC_POWER_MODE_INFO_REQUEST): "Diagnostic power mode info request",
    int(DOIP_DIAGNOSTIC_POWER_MODE_INFO_RESPONSE): "Power mode info response",
    int(DOIP_DIAGNOSTIC_MESSAGE): "Diagnostic message",
    int(DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE): "Diagnostic positive acknowledge",
    int(DOIP_DIAGNOSTIC_NEGATIVE_ACKNOWLEDGE): "Diagnostic negative acknowledge",
}

# to be changed later as an option in terminal
defaultTargetIPAddr = '172.26.200.101'
defaultTargetECUAddr = '2004'

def PadHexwithLead0s(hexStr):
    if isinstance (hexStr, str): # Make sure input argument is string
        if len(hexStr) % 2 != 0: # If the length is not even
             hexStr = '0' + hexStr # Add a leading '0' to get even length
    return hexStr

class DoIP_Client:
    def __init__(self, address='0', port=0, ECUAddr='1111'):

        # to do: need to add underscores for private properties...
        # init tcp socket
        self._localIPAddr = address
        
        # Reason for the if statement is that self._TCP_Socket.bind() does not seem to work in Windows when address == '0'
        if "Window" in platform.platform(): # Checks if software is running in the Windows OS
        
            # Use an netowrk interface IP address
            #
            # WARNING: If there are multiple IP addresses, the first IP address found will be used
            # The first IP address may not be the desired IP adress.
            # So it is recommended to temporarily close all other network interfaces used by the software
            self._localIPAddr = socket.gethostbyname(socket.getfqdn())
        
        self._localPort = port
        self._localECUAddr = ECUAddr
        self._targetIPAddr = None
        self._targetPort = None
        self._targetECUAddr = None
        self._isTCPConnected = False
        self._isRoutingActivated = False
        self._isVerbose = False
        self._TxDoIPMsg = DoIPMsg()
        self._RxDoIPMsg = DoIPMsg()
        self._logHndl = open('flash.log', 'w+')

        try:
            self._TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # self._TCP_Socket.setsockopt(socket.IPPROTO_TCP, 12, 1)#supposedly, 12 is TCP_QUICKACK option id
            self._TCP_Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # immediately send to wire wout delay
            self._TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                       1)  # allows different sockets to reuse ipaddress

            self._TCP_Socket.settimeout(5.0)
            # self._TCP_Socket.setblocking(1)
            self._TCP_Socket.bind((self._localIPAddr, self._localPort))
            #print "Socket successfully created: Bound to %s:%d" % (self._TCP_Socket.getsockname()[0], self._TCP_Socket.getsockname()[1])

        except socket.error as err:
            print "Error :: Socket creation failed with error: %s" % err
            if '[Errno 10049]' in str(err):
                print "Consider changing your machine's TCP settings so that it has a satic IP of 172.26.200.15"
            self._TCP_Socket = None

    def __enter__(self):
        return self

    def ConnectToDoIPServer(self, address=defaultTargetIPAddr, port=13400, routingActivation=True, targetECUAddr= '2004'):
        if self._isTCPConnected:
            print "Error :: Already connected to a server. Close the connection before starting a new one\n"
        else:
            if not self._TCP_Socket:
                print "Warning :: Socket was recently closed but no new socket was created.\nCreating new socket with last available IP address and Port"
                try:
                    self._TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # self._TCP_Socket.setsockopt(socket.IPPROTO_TCP, 12, 1)#supposedly, 12 is TCP_QUICKACK option id
                    self._TCP_Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # immediately send to wire wout delay
                    self._TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self._TCP_Socket.settimeout(5.0)
                    # self._TCP_Socket.setblocking(1)
                    self._TCP_Socket.bind((self._localIPAddr, self._localPort))
                    #print "Socket successfully created: Binded to %s:%d\n" % (self._TCP_Socket.getsockname()[0], self._TCP_Socket.getsockname()[1])
                except socket.error as err:
                    print "Error :: Socket creation failed with error %s" % (err)
                    self._TCP_Socket = None
                    return err
            if self._TCP_Socket != None:
                try:
                    #print "Connecting to DoIP Server at %s:%d... " % (address, port)
                    self._targetIPAddr = address
                    self._targetPort = port
                    self._TCP_Socket.connect((address, port))
                    self._isTCPConnected = True
                    #print "Connection to DoIP established\n"
                except socket.error as err:
                    print "Error :: Unable to connect to socket at %s:%d. Socket failed with error: %s" % (address, port, err)
                    self._targetIPAddr = None
                    self._targetPort = None
                    self._isTCPConnected = False
            else:
                return -1

        if routingActivation == False:
            return 0
        elif routingActivation == True and self._isTCPConnected:
            self._targetECUAddr = targetECUAddr
            if self.RequestRoutingActivation() == 0:
                return 0
            else:
                return -1
        elif routingActivation and not self._isTCPConnected:
            print "Error :: DoIP client is not connected to a server"
            return -1

    def DisconnectFromDoIPServer(self):
        if self._isTCPConnected:
            try:
                print "Disconnecting from DoIP server..."
                self._TCP_Socket.shutdown(socket.SHUT_RDWR)
                self._TCP_Socket.close()
                self._TCP_Socket = None
                self._isTCPConnected = 0
                print "Connection successfully shut down\n"
            except socket.error as err:
                print "Unable to disconnect from socket at %s:%d. Socket failed with error: %s." % (
                    self._targetIPAddr, self._targetPort, err)
                print "Warning :: Socket is currently in a metastable state."
            finally:
                self._targetIPAddr = None
                self._targetPort = None
                self._isTCPConnected = 0
        else:
            print "Error :: DoIP client is not connected to a server"

    def RequestRoutingActivation(self, activationType=DEFAULT_ACTIVATION, localECUAddr=None, targetECUAddr=None):
        if self._isTCPConnected:
            try:
                if not localECUAddr:
                    localECUAddr = self._localECUAddr
                if not targetECUAddr:
                    targetECUAddr = self._targetECUAddr
                DoIPHeader = PROTOCOL_VERSION + INVERSE_PROTOCOL_VERSION + DOIP_ROUTING_ACTIVATION_REQUEST
                payload = localECUAddr + activationType + ASRBISO + ASRBOEM
                payloadLength = "%.8X" % (len(payload) / 2)  # divide by 2 because 2 nibbles per byte
                activationString = DoIPHeader + payloadLength + payload
                self._TxDoIPMsg.UpdateMsg(activationString, self._isVerbose)
                if self._isVerbose:
                    print "Requesting routing activation..."
                    print "TCP SEND ::"
                    self._TxDoIPMsg.PrintMessage()
                self._TCP_Socket.send(activationString.decode("hex"))
                activationResponse = (binascii.hexlify(self._TCP_Socket.recv(2048))).upper()
                if self._isVerbose:
                    print "TCP RECV ::"
                DoIPResponse = DoIPMsg(activationResponse, self._isVerbose)
                if DoIPResponse.payload[0:2] == '10':
                    self._isRoutingActivated = True
                    self._targetECUAddr = DoIPResponse.targetAddress
                    if self._isVerbose:
                        print "Routing activated with ECU: %s\n" % (self._targetECUAddr)
                    return 0
                else:
                    self._isRoutingActivated = False
                    print "Unable to activate routing"
                    return -1
            except socket.error as err:
                print "Unable to activate routing with ECU:%.4X. Socket failed with error: %s" % (
                    int(targetECUAddr), err)
                self._isRoutingActivated = 0
                self._targetECUAddr = None
                return -1
        else:
            print "Unable to request routing activation. Currently not connected to a DoIP server"

    def _DoIPUDSSend(self, message, localECUAddr=None, targetECUAddr=None, logging=True):
        if self._isTCPConnected:
            try:
                if not localECUAddr:
                    localECUAddr = self._localECUAddr
                if not targetECUAddr:
                    targetECUAddr = self._targetECUAddr
                DoIPHeader = PROTOCOL_VERSION + INVERSE_PROTOCOL_VERSION + DOIP_DIAGNOSTIC_MESSAGE
                payload = self._localECUAddr + self._targetECUAddr + message  # no ASRBISO
                payloadLength = "%.8X" % (len(payload) / 2)
                UDSString = DoIPHeader + payloadLength + payload
                self._TxDoIPMsg.UpdateMsg(UDSString)
                if logging == True:
                    if self._TxDoIPMsg.isUDS:
                        self._logHndl.write('Client: ' + self._TxDoIPMsg.payload + '\n')
                    else:
                        self._logHndl.write('Client: ' + self._TxDoIPMsg.DecodePayloadType() + '\n')
                if self._isVerbose:
                    print "TCP SEND ::"
                    self._TxDoIPMsg.PrintMessage()
                self._TCP_Socket.send(UDSString.decode("hex"))
                return 0
            except socket.error as err:
                print "Unable to send UDS Message to ECU:%d. Socket failed with error: %s" % (targetECUAddr, err)
                return -1
        else:
            print "Not currently connected to a server"
            return -3

    def _DoIPUDSRecv(self, rxBufLen=1024, logging=True):
        if not self._isTCPConnected:
            raise IOError("Not currently connected to a server")

        if self._isVerbose: print "TCP RECV _DoIPUDSRecv::"
        self._RxDoIPMsg.UpdateMsg(binascii.hexlify(self._TCP_Socket.recv(rxBufLen)).upper(), self._isVerbose)
        if logging == True:
            if self._RxDoIPMsg.isUDS:
                self._logHndl.write('Server: ' + self._RxDoIPMsg.payload + '\n')
            else:
                self._logHndl.write('Server: ' + self._RxDoIPMsg.DecodePayloadType() + '\n')
        # check for positive ack, memory operation pending, or transfer operation pending
        if self._RxDoIPMsg.payloadType == DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE or \
                self._RxDoIPMsg.payload == PyUDS.MOPNDNG or \
                self._RxDoIPMsg.payload == PyUDS.TOPNDNG:
            if self._isVerbose: print "GOT ACK ::"
            return self._DoIPUDSRecv()
        elif self._RxDoIPMsg.payloadType == DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE:
            if self._isVerbose: print "GOT NACK ::"
            return (-2, None)
        else:
            if self._isVerbose: print "GOT POS Response :: " + self._RxDoIPMsg.payload
            return (0, self._RxDoIPMsg.payload)

    def DoIPReadDID(self, DID):
        if self._isVerbose: print "Request READ DID"
        self._DoIPUDSSend(PyUDS.RDBI + DID)
        return self._DoIPUDSRecv()

    def DoIPWriteDID(self, DID, msg):
        if self._isVerbose: print "Request Write DID"
        self._DoIPUDSSend(PyUDS.WDBI + DID + msg)
        return self._DoIPUDSRecv()

    def DoIPRoutineControl(self, subfunction, routine_id, op_data):
        if self._isVerbose: print "        Sending routine control command, subfunction:" + str(subfunction) + ", routine id:" + str(routine_id)
        self._DoIPUDSSend(PyUDS.RC + subfunction + routine_id + op_data)
        return self._DoIPUDSRecv()

    def DoIPEraseMemory(self, componentID):
        if self._isVerbose: print "Erasing memory..."
        
        if type(componentID) == 'int':
            componentID = '%0.2X' % (0xFF & componentID)
            
        componentID = PadHexwithLead0s(componentID)
        self._DoIPUDSSend(PyUDS.RC + PyUDS.STR + PyUDS.RC_EM + str(componentID))  # #  TO DO: CHANGE VALUE TO VARAIBLE
        return self._DoIPUDSRecv()

    def DoIPCheckMemory(self, componentID, CRCLen='00', CRC='00'):
        if self._isVerbose: print "Checking memory..."
        
        if type(componentID) == 'int':
            componentID = '%.2X' % (0xFF & componentID)
            
        componentID = PadHexwithLead0s(componentID)
        self._DoIPUDSSend(PyUDS.RC + PyUDS.STR + PyUDS.RC_CM + str(componentID) + CRCLen + CRC)
        return self._DoIPUDSRecv()

    def DoIPControlDTCSetting(self, msg):
        self._DoIPUDSSend(PyUDS.DCTS + msg)
        return self._DoIPUDSRecv()

    def DoIPSecurityAccess(self, msg):
        self._DoIPUDSSend(PyUDS.DSAREQ + msg)
        return self._DoIPUDSRecv()

    def DoIPCommunicationControl(self, msg):
        self._DoIPUDSSend(PyUDS.COMMUNICATION_CONTROL_SERVICE + msg)
        return self._DoIPUDSRecv()

    def DoIPSwitchDiagnosticSession(self, sessionID=1):
        if self._isVerbose: print "Request Switch Diagnostic Session, new session: ", sessionID
        targetSession = ''
        if int(sessionID) == 1:
            self._DoIPUDSSend(PyUDS.DSC + PyUDS.DS)
        elif int(sessionID) == 2:
            self._DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS)
        elif int(sessionID) == 3:
            self._DoIPUDSSend(PyUDS.DSC + PyUDS.EXTDS)
        else:
            raise ValueError("Invalid diagnostic session. Session ID: 1) Default session 2) Programming session 3) Extended session")

        return self._DoIPUDSRecv()

    def DoIPRequestDownload(self, memAddr, memSize, dataFormatID=PyUDS.DFI_00, addrLenFormatID=PyUDS.ALFID):
        if self._isVerbose:print "Requesting download data..."
        self._DoIPUDSSend(PyUDS.RD + dataFormatID + addrLenFormatID + memAddr + memSize)
        if (self._DoIPUDSRecv() == 0):
            if self._isVerbose:print "Request download data success\n"
            dlLenFormatID = int(self._RxDoIPMsg.payload[2], 16)  # number of bytes
        else:
            return -1
        return int(self._RxDoIPMsg.payload[4:(2 * dlLenFormatID + 4)], 16)

    def DoIPRequestDownloadKTM(self, msg):
        if self._isVerbose:print "Requesting download data..."
        self._DoIPUDSSend(PyUDS.RD + msg)
        return self._DoIPUDSRecv()

    def DoIPTransferData(self, blockIndex, data):
        self._DoIPUDSSend(PyUDS.TD + blockIndex + data)
        return self._DoIPUDSRecv()

    def DoIPRequestTransferExit(self):
        if self._isVerbose:print "Requesting transfer exit..."
        self._DoIPUDSSend(PyUDS.RTE)
        return self._DoIPUDSRecv()

    def SetVerbosity(self, verbose):
        self._isVerbose = verbose

    def Terminate(self):
        if self._isVerbose:print "Closing DoIP Client ..."
        self._TCP_Socket.close()
        self._logHndl.close()
        if self._isVerbose:print "Good bye"

    def __exit__(self, exc_type, exc_value, traceback):
        self.Terminate()


class DoIPMsg:
    def __init__(self, message=None, verbose=False):
        self.UpdateMsg(message, verbose)

    def UpdateMsg(self, message=None, verbose=False):
        if not message:
            self.messageString = None
            self.protcolVersion = self.inverseProtocolVersion = None
            self.payloadType = self.payloadLength = None
            self.sourceAddress = self.targetAddress = None
            self.payload = None
            self.isUDS = False
        else:
            self.messageString = message
            self.protcolVersion = message[0:2]
            self.inverseProtocolVersion = message[2:4]
            self.payloadType = message[4:8]
            self.payloadLength = message[8:16]
            self.sourceAddress = message[16:20]
            if self.payloadType == DOIP_ROUTING_ACTIVATION_REQUEST:
                self.targetAddress = None
            else:
                self.targetAddress = message[20:24]

            if self.payloadType == DOIP_DIAGNOSTIC_MESSAGE:
                self.isUDS = True
                self.payload = message[24:len(message)]
            else:
                self.payload = message[24:len(message) - len(ASRBISO)]
                self.isUDS = False
            if verbose:
                print "DoIPMsg: ", str(message)
                self.PrintMessage()

    def PrintMessage(self):
        print "Protocol Version         : " + str(self.protcolVersion)
        print "Inv. Protocol Version    : " + str(self.inverseProtocolVersion)
        print "Payload Type             : " + str(self.payloadType)
        print "Payload Type Description : " + str(self.DecodePayloadType(self.payloadType))
        print "Payload Length           : " + str(self.payloadLength)
        print "Source Address           : " + str(self.sourceAddress)
        print "Target Address           : " + str(self.targetAddress)
        print "Payload                  : " + str(self.payload)
        print ""

    def DecodePayloadType(self, payloadType=None):
        if payloadType == None:
            payloadType = self.payloadType
        return payloadTypeDescription.get(int(payloadType), "Invalid or unregistered diagnostic payload type")

def DoIP_Routine_Control(subfunction, routine, op, verbose=False):
    t_FlashStart = time.time()

    # start a DoIP client
    DoIPClient = DoIP_Client()
    DoIPClient.SetVerbosity(verbose)

    if DoIPClient._TCP_Socket:
        DoIPClient.ConnectToDoIPServer()

        if DoIPClient._isTCPConnected and DoIPClient._isRoutingActivated:
            
            if DoIPClient.DoIPRoutineControl(subfunction, routine, op):
                print "Successfully sent Routine Control Request: %s" % (subfunction+routine+op)
            else:
                print "Failed to send Routine Control Request: %s" % (subfunction+routine+op)

        else:
            print "Can not connect to DoIP Server."
    else:
        print "TCP Socket creation failed."


def readSegment(fileObj, segmentSize=2048):
    while True:
        segment = fileObj.read(segmentSize)
        if not segment:
            break
        yield segment

def calcChecksum16(segment, bytes):
    #print "calcChecksum16:"
    checksum = 0
    for b in segment:
        #print "b = ", b, ord(b)
        checksum += ord(b)
        #print "checksum: ", checksum

    return (checksum & 0x0000ffff)



def DoIP_Flash_Hex(componentID, flashFile, hostECUAddr = '0001', serverECUAddr = 'e000',targetIP='192.168.10.10', verbose=True, multiSegment=True, segmentSize=4096, blockSize=256):
    
    t_FlashStart = time.time()

    bytesRemaining = os.stat(flashFile).st_size

    if isinstance(segmentSize, list):
        segmentSize = segmentSize[0]

    if isinstance(blockSize, list):
        blockSize = blockSize[0]

    print "    flashing      " ,flashFile
    print "    file size     " ,bytesRemaining, "bytes"
    print "    segment size: ", segmentSize, "bytes"
    print "    block size:   ", blockSize, "bytes"
    print "    test addr :   ", hostECUAddr
    print "    server addr:  ", serverECUAddr
    print "    server IP:    ", targetIP

    #
    # start a DoIP client and connect to the server
    #
    DoIPClient = DoIP_Client(ECUAddr = hostECUAddr)
    DoIPClient.SetVerbosity(verbose)

    if not DoIPClient._TCP_Socket:
        raise IOError("TCP Setup Failed")

    downloadErr = False
    DoIPClient.ConnectToDoIPServer(address = targetIP, port = 13400, routingActivation = True, targetECUAddr = serverECUAddr)

    if not DoIPClient._isTCPConnected:
        raise IOError("TCP connection Failed")
        
    if not DoIPClient._isRoutingActivated:
        raise IOError("ISO 134000 Routing failed")

    if (segmentSize % blockSize != 0):
        raise ValueError("segment size must be a multiple of blocksize")

    print "\n=============================\n=== Pre-Progrmamming Step ===\n=============================\n"

    #
    # Retrieve Application Flash File Name
    #
    print "    ### Get Applicaiton Flash File Name"
    result, payload = DoIPClient.DoIPReadDID(PyUDS.DID_APPLICATION_FLASH_FILE_NAME)
    if result < 0 :
        raise ValueError("could not reterive DID_HEX_PROG_FILE_NAME")
    if payload == None:
        print "    Application Flash File Name: None\n"
    else:
        print "    Application Flash File Name: " + binascii.unhexlify(payload[6:]) + "\n"

    #
    # Retrieve Software Version Bootloader
    #
    print "    ### Get Software Version Number"
    result, payload = DoIPClient.DoIPReadDID(PyUDS.DID_BOOT_SW_ID)
    if result < 0 :
        raise ValueError("could not reterive DID_BOOT_SW_ID")
    if payload == None:
        print "    Application Flash File Name: None\n"
    else:
        print "    Application Flash File Name: " + binascii.unhexlify(payload[6:]) + "\n"



    #
    # Set sesson to Extended Diagnostic Session
    #
    print "    ### Switching to Extended Diagnostic Session"
    result, payload = DoIPClient.DoIPSwitchDiagnosticSession(PyUDS.EXTDS)
    print "        Result = ", result
    print "        payload = ", payload
    if result !=0:
        raise ValueError("Failed to switch to extended diagnostic session")
    # TODO: This shoudl get sent as a broadcast and not be ack'd by the server
    

    #
    # Control DTC Setting, DTC OFF
    #
    print "\n    ### Disable Non-Diagnostic Information"
    result, payload = DoIPClient.DoIPControlDTCSetting(PyUDS.DTC_OFF)
    print "        Result = ", result
    print "        payload = ", payload
    if result !=0:
        raise ValueError("Failed to switch to set DTC off")
    # TODO: This shoudl get sent as a broadcast and not be ack'd by the server


    #
    # Communication Control, Disable non-diagnostic communicaiton
    #
    print "\n    ### Disable Non-Diagnostic Information"
    result, payload = DoIPClient.DoIPCommunicationControl(PyUDS.DISABLE_RX_ENABLE_TX+PyUDS.NWMCM_NCM)
    print "        Result = ", result
    print "        payload = ", payload
    if result !=0:
        raise ValueError("Failed to switch to set DTC off")
    # TODO: This shoudl get sent as a broadcast and not be ack'd by the server


    print "\n=========================\n=== Progrmamming Step ===\n=========================\n"

    #
    # Set sesson to Programming Diagnostic Session
    #
    print "    ### Switching to Programming Diagnostic Session"
    result, payload = DoIPClient.DoIPSwitchDiagnosticSession(PyUDS.PRGS)
    print "        Result = ", result
    print "        payload = ", payload
    if result !=0:
        raise ValueError("Failed to switch to programming diagnostic session")


    #
    # Security Access: Request Seed
    #
    print "\n    ### TODO: Security Access: Request Seed"
    result, payload = DoIPClient.DoIPSecurityAccess(PyUDS.REQUEST_SEED)
    print "        Result = ", result
    print "        payload = ", payload
    if result !=0:
        raise ValueError("Failed to request security seed")
        

    #
    # Security Access: Send Key
    #
    print "\n    ### TODO: Security Access: Send Key"
    result, payload = DoIPClient.DoIPSecurityAccess(PyUDS.SEND_KEY + "22334455")
    print "        Result = ", result
    print "        payload = ", payload
    if result !=0:
        raise ValueError("Failed to request security seed")
        

    print "\n================================\n=== Enter Progrgramming Loop ===\n================================\n"
    print "%d bytesRemaining" % bytesRemaining
    print "%d bytes per segment" % 0, segmentSize
    print "%d bytes per transfer block" % blockSize

    imageOffset = 0
    bytesFlashed = 0
    segmentCount = 0

    flashFileObject = open(flashFile,'rb')
    print "Opened image file for reading"
    
    # 
    # read the segment into a buffer as we iterate through the generator
    # for the input file.
    #
    for segment in readSegment(flashFileObject, min(segmentSize, bytesRemaining)):
        currentImageOffset = imageOffset + bytesFlashed;
        currentSegmentOffset = 0
        bytesThisSegment = min(segmentSize, bytesRemaining)
        print "read segment %d into buffer, %d bytes" % (segmentCount, bytesThisSegment)

        eraseRunning = True
        while eraseRunning:
            #
            # Routine Control: Start Erase Memory
            #
            print "\n    ### Erase Memory, %d bytes at address %d" % (bytesThisSegment, currentImageOffset)
            #result, payload = DoIPClient.DoIPEraseMemoryKTM(currentImageOffset, currentImageOffset+bytesThisSegment)

            memStartAddr = currentImageOffset
            memEndAddr = memStartAddr + bytesThisSegment
            hMemStart = hex(memStartAddr).lstrip("0x").rstrip("L").rjust(8, '0') # convert 4096 to "001000"
            hMemEnd = hex(memEndAddr).lstrip("0x").rstrip("L").rjust(8, '0')

            command = PyUDS.START_ROUTINE + PyUDS.ERASE_MEMORY
            
            result, payload = DoIPClient.DoIPRoutineControl(PyUDS.START_ROUTINE , PyUDS.ERASE_MEMORY, hMemStart + hMemEnd)
            print "        Result = ", result
            print "        payload = ", payload
            if result !=0:
                raise ValueError("Failed to Start Erase Memory")

            #
            # Routine Control: Request Results Erase Memory
            #
            print "\n    ### Erase Memory Check Results"
            result, payload = DoIPClient.DoIPRoutineControl(PyUDS.REQUEST_ROUTINE_RESULTS, "FF00", "")
            print "        Result = ", result
            print "        payload = ", payload
            if result !=0:
                raise ValueError("Failed to request security seed")

            print "        General Routine Status", payload[8:10]
            print "        Erase result          ", payload[11:12]

            if result == 0 and payload[8:10] == "01":
                eraseRunning = False
        
            print "        Continue waiting for Erase More wait required=", eraseRunning
        #
        # Request Download 5.3.6
        #
        print "\n    ### Request Download 5.3.6"

        hAddressAndLengthFormatIdentifier = "44"
        hMemAddress = hex(currentImageOffset).lstrip("0x").rstrip("L").rjust(8, '0')
        hMemSize = hex(bytesThisSegment).lstrip("0x").rstrip("L").rjust(8, '0')

        print "    `formatter`:" + hAddressAndLengthFormatIdentifier + ", address:" + hMemAddress + ", size:" + hMemSize
        
        x = DoIPClient.DoIPRequestDownloadKTM(PyUDS.DATA_FORMAT_ID + hAddressAndLengthFormatIdentifier + hMemAddress + hMemSize)
        print x
#            result, payload = DoIPClient.DoIPRequestDownloadKTM(PyUDS.DATA_FORMAT_ID + hAddressAndLengthFormatIdentifier + "20305060")
        print "        Result = ", result
        print "        payload = ", payload
        if result !=0:
            raise ValueError("Failed to request security seed")


        #
        # Transfer Data 5.3.7
        #
        print "\n    ### Transfer Data"
        print "         blockSize:", blockSize
        print "         segmentSize:", segmentSize
        print "         bytesRemaining:", bytesRemaining
        print "         len(segment):", len(segment)
        
        blockSize = min(blockSize, bytesRemaining)
        blockCount = 0
        hexDataList = []
        blockByteCount = 0
        maxBlockByteCount = blockSize
        hexDataStr = ""

        segmentBytesRemaining = segmentSize
        
        while segmentBytesRemaining:
            minAddr = blockCount * blockSize
            maxAddr = minAddr + blockSize+1
            print "         minAddr:", minAddr
            print "         maxAddr:", maxAddr

            for address in range(minAddr, maxAddr + 1):
                # print '%.8X\t%.2X' % (address,ih[address])
                hexDataStr = hexDataStr + '%.2X' % ord(segment[address])
                blockByteCount += 1
                if blockByteCount == maxBlockByteCount:
                    hexDataList.append(hexDataStr)
                    hexDataStr = "" 
                    blockByteCount = 0
            hexDataList.append(hexDataStr)

            blockCount += 1
            #segmentBytesRemaining = min(0, segmentBytes-
            #
            ##


        print "%d elements in hexDataList" % len(hexDataList)
        for e in hexDataList:
            print len(e), e

        sys.exit()


        blockIndex = 0
        for block in hexDataList:
            blockIndexStr = '%.2X' % (blockIndex & 0xFF)
            print "blockindex: ", blockIndexStr
            print "block: ", block
            if DoIPClient.DoIPTransferData(blockIndexStr, block) != 0:
                downloadErr = True
                break
            bar.update(blockIndex)
            blockIndex += 1


        #
        # Request Transfer Exit 5.3.8
        #
        print "\n    ### Request Transfer Exit"
        result, payload = DoIPClient.DoIPRequestTransferExit()
        print "        Result = ", result
        print "        payload = ", payload
        if result !=0:
            raise ValueError("Failed to Start Erase Memory")

        #
        #   Routine Control, Request Checksum Results.
        #       31010201 Start Checksum
        #       ssssssss start address 32 bit
        #       eeeeeeee end address 32 bit
        #       cccc 16 bit checksum
        #
        print "\n    ### Routine Control, Start Checksum."

        # currentImageOffset: offset of this segment in the image.
        # bytesThisSegment: size of the current segment
        # this checksum 

        checksum16 = calcChecksum16(segment, bytesThisSegment)

        assert(len(segment) == bytesThisSegment)

        hMemStartAddress = hex(currentImageOffset).lstrip("0x").rstrip("L").rjust(8, '0')
        hMemEndaddress = hex(currentImageOffset+bytesThisSegment).lstrip("0x").rstrip("L").rjust(8, '0')
        hChecksum = hex(checksum16).lstrip("0x").rstrip("L").rjust(4, '0')



        result, payload = DoIPClient.DoIPRoutineControl(PyUDS.START_ROUTINE, "0201", hMemStartAddress+hMemEndaddress+hChecksum )
        print "        Result = ", result
        print "        payload = ", payload
        if result !=0:
            raise ValueError("Failed to Start Erase Memory")

        responseId = payload[0:2]
        subFunction = payload[2:4]
        checksum = payload[4:8]
        result = payload[8:10]

        print "        service     :", responseId
        print "        subfunction :", subFunction
        print "        checksum    :", checksum
        print "        result      :", result



        #
        # Routine Control: Verify checksum results
        #
        print "\n    ### Erase Memory Check Results"
        result, payload = DoIPClient.DoIPRoutineControl(PyUDS.REQUEST_ROUTINE_RESULTS, "0201", hChecksum )
        print "        Result = ", result
        print "        payload = ", payload
        if result !=0:
            raise ValueError("Failed to request security seed")

        responseId = payload[0:2]
        subFunction = payload[2:4]
        checksum = payload[4:8]
        routineStatus = payload[8:10]
        checksumResult = payload[10:12]


        print "        service       :", responseId
        print "        subfunction   :", subFunction
        print "        checksum      :", checksum
        print "        routineStatus :", routineStatus
        print "        checksumResult:", checksumResult


        #DoIPClient.DoIPRequestTransferExit()

        sys.exit()


        bytesFlashed += bytesThisSegment
        bytesRemaining -= bytesThisSegment
        segmentCount += 1

        print "end of flash cycle, %d bytes flashed, %d bytes remaining." % (bytesFlashed, bytesRemaining)

        #print "Exiting out of flash sequence...\n"
        #DoIPClient.DisconnectFromDoIPServer()

    #print "\n    ### Routine Control Checksum"

    #
    #   Routine Control, Request Checksum Results.
    #
    print "\n    ### Routine Control, Request Checksum Results."

    #
    # Write data by identifier, Dealer Number
    #
    print "\n    ### Write data by identifier, Dealer Number"

    #
    # Write data by identifier, Date of last Flash
    #
    print "\n    ### Write data by identifier, Date of last Flash"


    print "Exiting out of flash sequence...\n"
    DoIPClient.DisconnectFromDoIPServer()



def DoIP_DID_Access(verbose, did, writeVal=None, hostECUAddr = '0001', serverECUAddr = 'e000',targetIP='192.168.10.10'):
    DoIPClient = DoIP_Client(ECUAddr = hostECUAddr)
    DoIPClient.SetVerbosity(verbose)

    if not DoIPClient._TCP_Socket:
        raise IOError("TCP Setup Failed")

    downloadErr = False
    DoIPClient.ConnectToDoIPServer(address = targetIP, port = 13400, routingActivation = True, targetECUAddr = serverECUAddr)

    if not DoIPClient._isTCPConnected:
        raise IOError("TCP connection Failed")
        
    if not DoIPClient._isRoutingActivated:
        raise IOError("ISO 134000 Routing failed")

    print "    DID:      " ,did
    print "    writeVal: " ,writeVal
    print "    targetIP: ", targetIP

    if writeVal == None:
        #
        # Retrieve Application Flash File Name
        #
        print "    ### Query DID: ", did
        result, payload = DoIPClient.DoIPReadDID(did)
        if result < 0 :
            raise ValueError("could not reterive DID_HEX_PROG_FILE_NAME")

        print "result-data: ", payload[6:]

        # if it's all ascii, then print the acsii string
        stringVal = binascii.unhexlify(payload[6:])

        printable=True
        for c in stringVal:
            if ord(c) < 32 or ord(c) >= 127:
                printable = False

        if printable:
            print "string-value: ", stringVal
        else:
            print "not printable as a string..."



    print "ClosingDown...\n"
    DoIPClient.DisconnectFromDoIPServer()



def main():
    
    import argparse

    options = []
    parser = argparse.ArgumentParser()

    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')


    optional.add_argument("-f", "--file", nargs = 1, type = str, help = "Full path to flash file")
    optional.add_argument("-c", "--clientID", nargs = 1, default = ['0001'] ,type = str, help = "Host ECU id to flash from in hex format, i.e. 1111 will be read as 0x1111. Default: 1111")
    optional.add_argument("-s", "--serverID", nargs =1, default = ['E100'],type = str, help = "Target ECU id to flash to in hex format, i.e. 2004 will be read as 0x2004. Default: 2004")
    optional.add_argument("-t", "--targetIP", nargs = 1,default = ['192.168.10.10'], type = str, help = "Target IP address of ECU, e.g. 192.168.7.2. Default: 172.26.200.101")
    optional.add_argument("-S", "--segmentSize", nargs = 1, default = 4096 ,type = int, help = "Transfer segment size (file read size)")
    optional.add_argument("-B", "--blockSize", nargs = 1, default = 256 ,type = int, help = "Transfer command block size (transfer block)")
    optional.add_argument("-v", "--verbose", help="Set verbosity. Default: false", action="store_true")
    optional.add_argument("-d", "--did", nargs = 1, default = ['0001'] ,type = str, help="query/set DID, enter in hex format (e.g. FE08)")


    args = vars(parser.parse_args())


    if args['did']:
        print "DID Query/Set"
        DoIP_DID_Access(targetIP=args['targetIP'][0],          
                        verbose=args['verbose'], 
                        did = args['did'][0])
        sys.exit(1)

                           



    if not args['file']:
        print "Error:: No .swu file provided"			
        sys.exit(-1)

    if not args['clientID']:
        print "Error:: No host/client ECU address specified"
        sys.exit(-1)

    if not args['serverID']:
        print "Error:: No target/server ECU address specified"
        sys.exit(-1)

    if not args['targetIP']:
        print "Error:: No target IP address specified"
        sys.exit(-1)
                            
    if not args['segmentSize'] or args['segmentSize'] < 1:
        print "Error:: Invalid segmentSize, must be a positive integer"
        sys.exit(-1)

    if not args['blockSize'] or args['blockSize'] < 1 or  args['blockSize'] > args['segmentSize']:
        print "Error:: Invalid blockSize, must be a positive integer and no larger than a segment"
        sys.exit(-1)

    DoIP_Flash_Hex(0, args['file'][0], 
            targetIP=args['targetIP'][0], 
            verbose=args['verbose'], 
            multiSegment=True, 
            segmentSize = args['segmentSize'], 
            blockSize = args['blockSize'])

if __name__ == '__main__':
    main()

