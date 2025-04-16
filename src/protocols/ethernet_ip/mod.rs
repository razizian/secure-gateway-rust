/// EtherNet/IP command types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CommandType {
    ListIdentity = 0x63,
    ListServices = 0x64,
    ListInterfaces = 0x65,
    RegisterSession = 0x66,
    UnregisterSession = 0x67,
    SendRRData = 0x6F,
    SendUnitData = 0x70,
    DataRequest = 0x0A,
    DataResponse = 0x0B,
    Custom(u8),
}