#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modbus TCP 协议模拟器
支持多种Modbus功能码，模拟工业设备数据
"""

import asyncio
import yaml
import random
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from loguru import logger
from pymodbus.server.async_io import ModbusTcpServer, ServerAsyncStop
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadBuilder, BinaryPayloadDecoder
from pymodbus.pdu import ModbusRequest, ModbusResponse
from pymodbus.framer import ModbusSocketFramer


@dataclass
class ModbusConfig:
    """Modbus配置类"""
    host: str = "0.0.0.0"
    port: int = 502
    unit_id: int = 1


@dataclass
class DataConfig:
    """数据配置类"""
    coils_start: int = 0
    coils_count: int = 100
    discrete_inputs_start: int = 10000
    discrete_inputs_count: int = 100
    holding_registers_start: int = 40000
    holding_registers_count: int = 1000
    input_registers_start: int = 30000
    input_registers_count: int = 1000


def log_packet_hex(data: bytes, is_request: bool = True, client_addr: str = ""):
    """以十六进制格式记录报文"""
    if not data:
        return
    
    hex_str = ' '.join(f'{b:02X}' for b in data)
    packet_type = "接收请求" if is_request else "发送响应"
    
    logger.info(f"{'='*70}")
    if client_addr:
        logger.info(f"[{client_addr}] {packet_type} (长度: {len(data)} 字节)")
    else:
        logger.info(f"{packet_type} (长度: {len(data)} 字节)")
    logger.info(f"HEX: {hex_str}")
    
    # 解析MBAP头（Modbus TCP）
    if len(data) >= 7:
        transaction_id = (data[0] << 8) | data[1]
        protocol_id = (data[2] << 8) | data[3]
        length = (data[4] << 8) | data[5]
        unit_id = data[6]
        
        logger.info(f"事务ID: {transaction_id}, 协议ID: {protocol_id}, 长度: {length}, 单元ID: {unit_id}")
        
        if len(data) >= 8:
            function_code = data[7]
            fc_names = {
                1: "读线圈(01)", 2: "读离散输入(02)", 
                3: "读保持寄存器(03)", 4: "读输入寄存器(04)",
                5: "写单个线圈(05)", 6: "写单个寄存器(06)",
                15: "写多个线圈(0F)", 16: "写多个寄存器(10)",
                0x83: "异常响应-读保持寄存器(83)"
            }
            fc_name = fc_names.get(function_code, f"未知({function_code:02X})")
            logger.info(f"功能码: {fc_name}")
            
            # 检查是否为异常响应
            if function_code >= 0x80:
                if len(data) >= 9:
                    exception_code = data[8]
                    exception_names = {
                        1: "非法功能", 2: "非法数据地址", 3: "非法数据值",
                        4: "从站设备故障", 5: "确认", 6: "从站设备忙"
                    }
                    exception_name = exception_names.get(exception_code, f"未知异常({exception_code})")
                    logger.error(f"❌ 异常码: {exception_code} - {exception_name}")
            # 解析请求参数
            elif is_request and len(data) >= 12:
                if function_code in [1, 2, 3, 4]:  # 读操作
                    start_addr = (data[8] << 8) | data[9]
                    count = (data[10] << 8) | data[11]
                    logger.info(f"起始地址: {start_addr}, 数量: {count}")
                elif function_code in [5, 6]:  # 写单个
                    addr = (data[8] << 8) | data[9]
                    value = (data[10] << 8) | data[11]
                    logger.info(f"地址: {addr}, 值: {value}")
                elif function_code in [15, 16]:  # 写多个
                    start_addr = (data[8] << 8) | data[9]
                    count = (data[10] << 8) | data[11]
                    logger.info(f"起始地址: {start_addr}, 数量: {count}")
            # 解析正常响应
            elif not is_request and function_code in [3, 4]:
                if len(data) >= 9:
                    byte_count = data[8]
                    logger.info(f"字节数: {byte_count}")
                    if len(data) >= 9 + byte_count:
                        values = []
                        for i in range(0, byte_count, 2):
                            if 9 + i + 1 < len(data):
                                value = (data[9 + i] << 8) | data[9 + i + 1]
                                values.append(value)
                        logger.info(f"寄存器值: {values[:10]}{'...' if len(values) > 10 else ''}")
    
    logger.info(f"{'='*70}")


class ModbusTcpProtocolWithLogging(asyncio.Protocol):
    """带日志记录的Modbus TCP协议处理器"""
    
    def __init__(self, context, identity=None):
        self.context = context
        self.identity = identity
        self.transport = None
        self.client_address = None
        self.buffer = b''
    
    def connection_made(self, transport):
        """客户端连接时"""
        self.transport = transport
        self.client_address = transport.get_extra_info('peername')
        logger.success(f"✅ 客户端已连接: {self.client_address}")
    
    def connection_lost(self, exc):
        """客户端断开连接时"""
        logger.warning(f"❌ 客户端已断开: {self.client_address}")
        if exc:
            logger.error(f"连接异常: {exc}")
    
    def data_received(self, data):
        """接收到数据时"""
        try:
            self.buffer += data
            
            # Modbus TCP报文至少需要8字节（MBAP头7字节 + 功能码1字节）
            while len(self.buffer) >= 8:
                # 读取报文长度
                if len(self.buffer) < 6:
                    break
                    
                length = (self.buffer[4] << 8) | self.buffer[5]
                frame_length = length + 6  # MBAP头6字节 + PDU长度
                
                if len(self.buffer) < frame_length:
                    # 数据不完整，等待更多数据
                    break
                
                # 提取完整帧
                frame = self.buffer[:frame_length]
                self.buffer = self.buffer[frame_length:]
                
                # 记录接收到的请求报文
                log_packet_hex(frame, is_request=True, client_addr=str(self.client_address))
                
                # 处理请求
                response_frame = self._process_frame(frame)
                
                if response_frame:
                    # 记录发送的响应报文
                    log_packet_hex(response_frame, is_request=False, client_addr=str(self.client_address))
                    
                    # 发送响应
                    self.transport.write(response_frame)
                    
        except Exception as e:
            logger.error(f"处理接收数据时出错: {e}", exc_info=True)
    
    def _process_frame(self, frame):
        """处理Modbus帧"""
        try:
            if len(frame) < 8:
                return self._build_exception_response(frame, 0x04)  # 从站设备故障
            
            # 解析MBAP头
            transaction_id = (frame[0] << 8) | frame[1]
            protocol_id = (frame[2] << 8) | frame[3]
            length = (frame[4] << 8) | frame[5]
            unit_id = frame[6]
            function_code = frame[7]
            
            # 检查协议ID
            if protocol_id != 0:
                return self._build_exception_response(frame, 0x04)
            
            # 获取从设备上下文
            slave = self.context[unit_id]
            if not slave:
                return self._build_exception_response(frame, 0x04)
            
            # 处理不同的功能码
            try:
                if function_code == 0x03:  # 读保持寄存器
                    return self._handle_read_holding_registers(frame, slave)
                elif function_code == 0x04:  # 读输入寄存器
                    return self._handle_read_input_registers(frame, slave)
                elif function_code == 0x01:  # 读线圈
                    return self._handle_read_coils(frame, slave)
                elif function_code == 0x02:  # 读离散输入
                    return self._handle_read_discrete_inputs(frame, slave)
                elif function_code == 0x06:  # 写单个寄存器
                    return self._handle_write_single_register(frame, slave)
                elif function_code == 0x10:  # 写多个寄存器
                    return self._handle_write_multiple_registers(frame, slave)
                else:
                    # 不支持的功能码
                    return self._build_exception_response(frame, 0x01)
            except Exception as e:
                logger.error(f"处理功能码 {function_code:02X} 时出错: {e}")
                return self._build_exception_response(frame, 0x04)
                
        except Exception as e:
            logger.error(f"处理帧时出错: {e}", exc_info=True)
            return None
    
    def _handle_read_holding_registers(self, frame, slave):
        """处理读保持寄存器"""
        if len(frame) < 12:
            return self._build_exception_response(frame, 0x03)
        
        start_addr = (frame[8] << 8) | frame[9]
        count = (frame[10] << 8) | frame[11]
        
        # 验证数量
        if count < 1 or count > 125:
            return self._build_exception_response(frame, 0x03)
        
        # 读取寄存器
        try:
            values = slave.getValues(3, start_addr, count)  # 3 = 保持寄存器
            
            # 构建响应
            byte_count = count * 2
            response = bytearray(frame[:6])  # 复制MBAP头
            response[4] = 0  # 更新长度字段
            response[5] = byte_count + 3  # 单元ID + 功能码 + 字节数 + 数据
            response.append(frame[6])  # 单元ID
            response.append(0x03)  # 功能码
            response.append(byte_count)  # 字节数
            
            # 添加寄存器值
            for value in values:
                response.append((value >> 8) & 0xFF)
                response.append(value & 0xFF)
            
            return bytes(response)
        except Exception as e:
            logger.error(f"读取保持寄存器失败: {e}")
            return self._build_exception_response(frame, 0x02)  # 非法数据地址
    
    def _handle_read_input_registers(self, frame, slave):
        """处理读输入寄存器"""
        if len(frame) < 12:
            return self._build_exception_response(frame, 0x03)
        
        start_addr = (frame[8] << 8) | frame[9]
        count = (frame[10] << 8) | frame[11]
        
        if count < 1 or count > 125:
            return self._build_exception_response(frame, 0x03)
        
        try:
            values = slave.getValues(4, start_addr, count)  # 4 = 输入寄存器
            
            byte_count = count * 2
            response = bytearray(frame[:6])
            response[4] = 0
            response[5] = byte_count + 3
            response.append(frame[6])
            response.append(0x04)
            response.append(byte_count)
            
            for value in values:
                response.append((value >> 8) & 0xFF)
                response.append(value & 0xFF)
            
            return bytes(response)
        except Exception as e:
            logger.error(f"读取输入寄存器失败: {e}")
            return self._build_exception_response(frame, 0x02)
    
    def _handle_read_coils(self, frame, slave):
        """处理读线圈"""
        if len(frame) < 12:
            return self._build_exception_response(frame, 0x03)
        
        start_addr = (frame[8] << 8) | frame[9]
        count = (frame[10] << 8) | frame[11]
        
        if count < 1 or count > 2000:
            return self._build_exception_response(frame, 0x03)
        
        try:
            values = slave.getValues(1, start_addr, count)  # 1 = 线圈
            
            byte_count = (count + 7) // 8
            response = bytearray(frame[:6])
            response[4] = 0
            response[5] = byte_count + 3
            response.append(frame[6])
            response.append(0x01)
            response.append(byte_count)
            
            for byte_idx in range(byte_count):
                byte_val = 0
                for bit_idx in range(8):
                    val_idx = byte_idx * 8 + bit_idx
                    if val_idx < count and values[val_idx]:
                        byte_val |= (1 << bit_idx)
                response.append(byte_val)
            
            return bytes(response)
        except Exception as e:
            logger.error(f"读取线圈失败: {e}")
            return self._build_exception_response(frame, 0x02)
    
    def _handle_read_discrete_inputs(self, frame, slave):
        """处理读离散输入"""
        if len(frame) < 12:
            return self._build_exception_response(frame, 0x03)
        
        start_addr = (frame[8] << 8) | frame[9]
        count = (frame[10] << 8) | frame[11]
        
        if count < 1 or count > 2000:
            return self._build_exception_response(frame, 0x03)
        
        try:
            values = slave.getValues(2, start_addr, count)  # 2 = 离散输入
            
            byte_count = (count + 7) // 8
            response = bytearray(frame[:6])
            response[4] = 0
            response[5] = byte_count + 3
            response.append(frame[6])
            response.append(0x02)
            response.append(byte_count)
            
            for byte_idx in range(byte_count):
                byte_val = 0
                for bit_idx in range(8):
                    val_idx = byte_idx * 8 + bit_idx
                    if val_idx < count and values[val_idx]:
                        byte_val |= (1 << bit_idx)
                response.append(byte_val)
            
            return bytes(response)
        except Exception as e:
            logger.error(f"读取离散输入失败: {e}")
            return self._build_exception_response(frame, 0x02)
    
    def _handle_write_single_register(self, frame, slave):
        """处理写单个寄存器"""
        if len(frame) < 12:
            return self._build_exception_response(frame, 0x03)
        
        addr = (frame[8] << 8) | frame[9]
        value = (frame[10] << 8) | frame[11]
        
        try:
            slave.setValues(3, addr, [value])
            # 写单个寄存器的响应就是回显请求
            return frame
        except Exception as e:
            logger.error(f"写单个寄存器失败: {e}")
            return self._build_exception_response(frame, 0x02)
    
    def _handle_write_multiple_registers(self, frame, slave):
        """处理写多个寄存器"""
        if len(frame) < 13:
            return self._build_exception_response(frame, 0x03)
        
        start_addr = (frame[8] << 8) | frame[9]
        count = (frame[10] << 8) | frame[11]
        byte_count = frame[12]
        
        if count < 1 or count > 123 or byte_count != count * 2:
            return self._build_exception_response(frame, 0x03)
        
        if len(frame) < 13 + byte_count:
            return self._build_exception_response(frame, 0x03)
        
        try:
            values = []
            for i in range(count):
                value = (frame[13 + i * 2] << 8) | frame[13 + i * 2 + 1]
                values.append(value)
            
            slave.setValues(3, start_addr, values)
            
            # 构建响应
            response = bytearray(frame[:12])
            response[4] = 0
            response[5] = 6
            return bytes(response)
        except Exception as e:
            logger.error(f"写多个寄存器失败: {e}")
            return self._build_exception_response(frame, 0x02)
    
    def _build_exception_response(self, frame, exception_code):
        """构建异常响应"""
        if len(frame) < 8:
            return None
        
        response = bytearray(frame[:6])
        response[4] = 0
        response[5] = 3
        response.append(frame[6])  # 单元ID
        response.append(frame[7] | 0x80)  # 功能码 + 0x80
        response.append(exception_code)
        
        return bytes(response)


class CustomModbusServerContext(ModbusServerContext):
    """自定义Modbus服务器上下文，用于拦截和记录所有请求/响应"""
    
    def __init__(self, slaves=None, single=True):
        super().__init__(slaves=slaves, single=True)
        self.request_count = 0


class ModbusDataStore:
    """Modbus数据存储类"""
    
    def __init__(self, config: DataConfig):
        self.config = config
        self._initialize_data_blocks()
        
    def _initialize_data_blocks(self):
        """初始化数据块"""
        # 注意: Modbus数据块内部使用从0开始的地址
        # 40000等大地址只是Modbus地址表示规范，内部存储从0开始
        
        # 线圈状态 (Coils) - 布尔值
        self.coils = ModbusSequentialDataBlock(
            0,  # 内部地址从0开始
            [False] * self.config.coils_count
        )
        
        # 离散输入 (Discrete Inputs) - 布尔值
        self.discrete_inputs = ModbusSequentialDataBlock(
            0,  # 内部地址从0开始
            [False] * self.config.discrete_inputs_count
        )
        
        # 保持寄存器 (Holding Registers) - 16位整数
        self.holding_registers = ModbusSequentialDataBlock(
            0,  # 内部地址从0开始
            [0] * self.config.holding_registers_count
        )
        
        # 输入寄存器 (Input Registers) - 16位整数
        self.input_registers = ModbusSequentialDataBlock(
            0,  # 内部地址从0开始
            [0] * self.config.input_registers_count
        )
        
        # 初始化一些模拟数据
        self._initialize_simulation_data()
        
    def _initialize_simulation_data(self):
        """初始化模拟数据"""
        # 初始化线圈状态
        for i in range(min(10, self.config.coils_count)):
            self.coils.setValues(i, [i % 2 == 0])
            
        # 初始化离散输入
        for i in range(min(10, self.config.discrete_inputs_count)):
            self.discrete_inputs.setValues(i, [i % 3 == 0])
            
        # 初始化保持寄存器 - 模拟温度、压力等传感器数据
        for i in range(min(50, self.config.holding_registers_count)):
            if i % 10 == 0:  # 温度数据
                self.holding_registers.setValues(i, [2000 + i * 10])  # 20.00°C + 偏移
            elif i % 10 == 1:  # 压力数据
                self.holding_registers.setValues(i, [1000 + i * 5])   # 10.00 bar + 偏移
            elif i % 10 == 2:  # 流量数据
                self.holding_registers.setValues(i, [500 + i * 2])    # 5.00 L/min + 偏移
            else:
                self.holding_registers.setValues(i, [i * 100])
                
        # 初始化输入寄存器 - 模拟实时数据
        for i in range(min(50, self.config.input_registers_count)):
            self.input_registers.setValues(i, [random.randint(0, 65535)])
    
    def update_simulation_data(self):
        """更新模拟数据"""
        # 更新输入寄存器数据 - 模拟实时变化
        for i in range(min(20, self.config.input_registers_count)):
            try:
                values = self.input_registers.getValues(i, 1)
                if values and len(values) > 0:
                    current_value = values[0]
                    # 随机变化 ±10%
                    change = int(current_value * 0.1 * (random.random() - 0.5))
                    new_value = max(0, min(65535, current_value + change))
                    self.input_registers.setValues(i, [new_value])
            except Exception as e:
                logger.debug(f"更新输入寄存器 {i} 失败: {e}")
            
        # 更新一些保持寄存器数据
        for i in range(0, min(10, self.config.holding_registers_count), 10):
            try:
                values = self.holding_registers.getValues(i, 1)
                if values and len(values) > 0:
                    current_value = values[0]
                    # 温度数据缓慢变化
                    change = random.randint(-50, 50)  # ±0.5°C
                    new_value = max(0, min(65535, current_value + change))
                    self.holding_registers.setValues(i, [new_value])
            except Exception as e:
                logger.debug(f"更新保持寄存器 {i} 失败: {e}")


class ModbusSimulator:
    """Modbus TCP模拟器主类"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self.data_store = ModbusDataStore(self._parse_data_config())
        self.server_context = None
        self._setup_logging()
        
    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            logger.warning(f"配置文件 {self.config_file} 不存在，使用默认配置")
            return self._get_default_config()
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'server': {
                'host': '0.0.0.0',
                'port': 502,
                'unit_id': 1
            },
            'data': {
                'coils': {'start_address': 0, 'count': 100, 'initial_value': False},
                'discrete_inputs': {'start_address': 10000, 'count': 100, 'initial_value': False},
                'holding_registers': {'start_address': 40000, 'count': 1000, 'initial_value': 0},
                'input_registers': {'start_address': 30000, 'count': 1000, 'initial_value': 0}
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/simsrv.log',
                'rotation': '10 MB',
                'retention': '7 days'
            }
        }
    
    def _parse_data_config(self) -> DataConfig:
        """解析数据配置"""
        data_config = self.config.get('data', {})
        
        coils_config = data_config.get('coils', {})
        discrete_inputs_config = data_config.get('discrete_inputs', {})
        holding_registers_config = data_config.get('holding_registers', {})
        input_registers_config = data_config.get('input_registers', {})
        
        return DataConfig(
            coils_start=coils_config.get('start_address', 0),
            coils_count=coils_config.get('count', 100),
            discrete_inputs_start=discrete_inputs_config.get('start_address', 10000),
            discrete_inputs_count=discrete_inputs_config.get('count', 100),
            holding_registers_start=holding_registers_config.get('start_address', 40000),
            holding_registers_count=holding_registers_config.get('count', 1000),
            input_registers_start=input_registers_config.get('start_address', 30000),
            input_registers_count=input_registers_config.get('count', 1000)
        )
    
    def _setup_logging(self):
        """设置日志"""
        import logging
        
        log_config = self.config.get('logging', {})
        
        # 移除默认处理器
        logger.remove()
        
        # 添加控制台输出 - 使用DEBUG级别以显示更多信息
        logger.add(
            sink=lambda msg: print(msg, end=""),
            level="DEBUG",
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>"
        )
        
        # 添加文件输出
        log_file = log_config.get('file', 'logs/simsrv.log')
        logger.add(
            sink=log_file,
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            rotation=log_config.get('rotation', '10 MB'),
            retention=log_config.get('retention', '7 days'),
            encoding='utf-8'
        )
        
        # 启用pymodbus库的DEBUG日志
        # 这将显示所有Modbus请求和响应的详细信息
        pymodbus_logger = logging.getLogger('pymodbus')
        pymodbus_logger.setLevel(logging.DEBUG)
        
        # 创建控制台处理器用于pymodbus日志
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '\033[32m%(asctime)s\033[0m | \033[34mDEBUG   \033[0m | [pymodbus] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        pymodbus_logger.addHandler(console_handler)
        
        logger.info("已启用pymodbus调试日志")
    
    def _create_server_context(self):
        """创建服务器上下文"""
        # 创建从设备上下文
        slave_context = ModbusSlaveContext(
            di=self.data_store.discrete_inputs,  # 离散输入
            co=self.data_store.coils,            # 线圈
            hr=self.data_store.holding_registers, # 保持寄存器
            ir=self.data_store.input_registers   # 输入寄存器
        )
        
        # 创建自定义服务器上下文以拦截请求/响应
        self.server_context = CustomModbusServerContext(slaves=slave_context, single=True)
        
        # 设置设备标识
        identity = ModbusDeviceIdentification()
        identity.VendorName = 'SimSrv'
        identity.ProductCode = 'SIM'
        identity.VendorUrl = 'https://github.com/simsrv'
        identity.ProductName = 'Modbus TCP Simulator'
        identity.ModelName = 'SimSrv-1.0'
        identity.MajorMinorRevision = '1.0.0'
        
        return identity
    
    async def start_server(self):
        """启动Modbus TCP服务器"""
        try:
            identity = self._create_server_context()
            
            server_config = self.config['server']
            host = server_config['host']
            port = server_config['port']
            
            logger.info(f"正在启动 Modbus TCP 模拟器...")
            logger.info(f"服务器地址: {host}:{port}")
            logger.info(f"单元ID: {server_config['unit_id']}")
            logger.info(f"调试模式: 已启用完整报文日志")
            
            # 创建自定义的TCP服务器来拦截数据包
            loop = asyncio.get_event_loop()
            
            # 创建服务器 - 使用lambda创建协议工厂
            server = await loop.create_server(
                lambda: ModbusTcpProtocolWithLogging(self.server_context, identity),
                host,
                port
            )
            
            logger.success(f"✅ Modbus TCP 服务器已成功启动在 {host}:{port}")
            
            async with server:
                await server.serve_forever()
            
        except Exception as e:
            logger.error(f"启动服务器失败: {e}", exc_info=True)
            raise
    
    async def data_simulation_task(self):
        """数据模拟任务"""
        while True:
            try:
                self.data_store.update_simulation_data()
                await asyncio.sleep(1)  # 每秒更新一次数据
            except Exception as e:
                logger.error(f"数据模拟任务错误: {e}")
                await asyncio.sleep(5)


async def main():
    """主函数"""
    try:
        # 创建模拟器实例
        simulator = ModbusSimulator()
        
        logger.info("Modbus TCP 模拟器已启动")
        logger.info("支持的 Modbus 功能码:")
        logger.info("  01: 读线圈状态")
        logger.info("  02: 读离散输入")
        logger.info("  03: 读保持寄存器")
        logger.info("  04: 读输入寄存器")
        logger.info("  05: 写单个线圈")
        logger.info("  06: 写单个寄存器")
        logger.info("  15: 写多个线圈")
        logger.info("  16: 写多个寄存器")
        logger.info("按 Ctrl+C 停止服务器")
        
        # 创建数据模拟任务
        simulation_task = asyncio.create_task(simulator.data_simulation_task())
        
        # 启动服务器 (这会阻塞直到服务器停止)
        await simulator.start_server()
        
    except KeyboardInterrupt:
        logger.info("收到停止信号，正在关闭服务器...")
    except Exception as e:
        logger.error(f"服务器运行错误: {e}")
    finally:
        logger.info("Modbus TCP 模拟器已停止")


if __name__ == "__main__":
    # 创建日志目录
    import os
    os.makedirs("logs", exist_ok=True)
    
    # 运行主程序
    asyncio.run(main())
