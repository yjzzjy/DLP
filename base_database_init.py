# @Time     :2022/1/10  21:15
# @Author   : yaojianhzhong
import copy

import IPy
from mongodb_base import Mongodb
from scaner_config import *
from Switch_port_check import Port_check


def create_base_collections(col_name, net):
    """
    生成各场景的基础数据集合
    :param col_name: 集合名称
    涉密信息
    :param net: IP段
    :return:
    """
    GRE = Mongodb("127.0.0.1", "GRE_ENV")
    GRE.login()
    index_unique = "ip"    # 唯一索引
    ips = IPy.IP(net)
    ip_lis = [str(x) for x in ips]
    moudle = {
        "ip": "",
        "is_used": False,     # 基线是否使用
        "user": "",
        "case": col_name,
        "scan_used": False,   # 扫描结果是否使用
        "is_except": False,  # 特殊IP使用声明
        "chek_result": True,  # 校验使用情况是否匹配
        "is_useless": False,    # 已登记IP扫描结果中未使用
        "is_unregistered": False,  # 扫描到的IP未登记
        "useless_count": 0   # 如果多次扫描未使用，提示释放资源
    }  # 数据记录模板
    data_lis = []
    for ip in ip_lis:
        moudle["ip"] = ip
        data = copy.deepcopy(moudle)
        data_lis.append(data)
    GRE.delet_collection(col_name)    # 初始化数据库，清楚集合
    GRE.create_index(col_name, index_unique, unique=True)  # 设置唯一索引
    GRE.insert_data(col_name, data_lis)
    GRE.close()


def create_base_collections_port(col_name, port_lis):
    """
    生成设备端口信息集合
    :param col_name:
    :param port_lis:
    :return:
    """
    GRE = Mongodb("127.0.0.1", "GRE_ENV")
    GRE.login()
    index_unique = "port"  # 唯一索引
    moudle = {
        "port": "",
        "is_used": False,  # 基线是否使用
        "user": "",
        "case": "",
        "scan_used": False,  # 扫描结果是否使用
        "chek_result": True,  # 校验使用情况是否匹配
        "is_useless": False,  # 已登记扫描结果中未使用
        "is_unregistered": False,  # 扫描到的未登记
    }  # 数据记录模板
    data_lis = []
    for port in port_lis:
        moudle["port"] = port
        data = copy.deepcopy(moudle)
        data_lis.append(data)
    GRE.delet_collection(col_name)  # 初始化数据库，清楚集合
    GRE.create_index(col_name, index_unique, unique=True)  # 设置唯一索引
    GRE.insert_data(col_name, data_lis)
    GRE.close()


if __name__ == '__main__':
    # IP信息集合
    for key, vlaue in env_dict.items():
        create_base_collections(key, vlaue)

    # 交换机端口集合
    switch = Port_check(Mgt_access_Switch, Mgt_access_user, Mgt_access_paassword)
    switch.login()
    port_lis = switch.get_port_all()
    switch.logout()
    create_base_collections_port("管控TOR_240.6", port_lis)

    switch = Port_check(yw_access_Switch, yw_access_user, yw_access_paassword)
    switch.login()
    port_lis = switch.get_port_all()
    switch.logout()
    create_base_collections_port("业务TOR_240.4", port_lis)
