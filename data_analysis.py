# @Time     :2022/1/10  22:27
# @Author   : yaojianhzhong

import xlwings as xw
import time
from threading import Thread
from net_scaner import Scanner
from scaner_config import *
from mongodb_base import Mongodb



class Data_Analysis(Mongodb):
    def __init__(self, host, database, port=27017):
        Mongodb.__init__(self, host, database, port)
        self.path = r'E:\Python_workespace\GRE_environment\check_result\env_info_{}.xlsx'.format(time.time())
        self.scan_result = {}
        self.base_excel = r"E:\Python_workespace\GRE_environment\Base_info\network_check_basecofig.xlsx"
        self.port_base_excel = r"E:\Python_workespace\GRE_environment\Base_info\port_baseconfig.xlsx"

    @staticmethod
    def make_ip(ip_info, mode=0):
        """
        IP转换, 仅适用于公共管理资源
        :param ip_info: 地址信息
        涉密信息
        芯片测试
        :param mode: 0：地址信息为32位地址，去最后一段数字
                     1：地址信息是D段的数字，组合上管理地址的前缀
        :return:
        """
        if mode == 0:
            result = ip_info.split('.')[3]
            return result
        if mode == 1:
            net = scan_net.split('.')[0:3]
            net.append(str(ip_info))
            result = '.'.join(net)
            return result

    def set_base_used(self, collection):
        """根据基线excel更新使用is_used字段"""
        wb = xw.Book(self.base_excel)
        sht = wb.sheets.active
        cols = ['J', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I']
        for num in range(1, 255):
            col = cols[num % 10]  # 定位列数
            if not num % 10 == 0:
                row = num // 10 + 1  # 定位行数
            else:
                row = num // 10
            locate = col + str(row)
            color_base = sht.range(locate).color
            if color_base in color_lis:
                ip = self.make_ip(int(sht.range(locate).value), 1)
                self.modify_data(collection, {"ip": ip}, {"is_used": True})
            else:
                ip = self.make_ip(int(sht.range(locate).value), 1)
                self.modify_data(collection, {"ip": ip}, {"is_used": False})
        wb.close()

    def set_scan_used(self, collection, ip_list):
        """根据扫描结果更新scaner_used字段"""
        # 初始化数据，防止历史数据残留
        self.modify_data(collection, {}, {"scan_used": False})
        for ip in ip_list:
            self.modify_data(collection, {"ip": ip}, {"scan_used": True})

    def set_except_used(self, collection):
        """根据例外IP更新scaner_used字段"""
        # 初始化数据
        self.modify_data(collection, {}, {"is_except": False})
        for ip in range(exception_ips[0], exception_ips[1]+1):
            ip = self.make_ip(ip, 1)
            self.modify_data(collection, {"ip": ip}, {"is_except": True})

    def check_ip(self):
        """检查公共资源使用情况"""
        collection = "公共管理"
        # 初始化数据
        self.modify_data(collection, {}, {"chek_result": True, "is_useless": False, "is_unregistered": False})
        # 更新数据校验结果
        # 登记未使用
        self.modify_data(collection, {"is_used": True, "scan_used": False}, {"chek_result": False, "is_useless": True})
        # 未使用的IP记录次数
        useless = self.search_data(collection, {"ip": 1, "useless_count": 1, "is_useless": True})
        for info in useless:
            ip = info["ip"]
            count = info["useless_count"] + 1
            self.modify_data(collection, {"ip": ip}, {"useless_count": count})
        # 使用未登记
        self.modify_data(collection, {"is_used": False, "scan_used": True}, {"chek_result": False, "is_unregistered": True})
        # 排除例外地址（SSLVPN地址池）
        self.modify_data(collection, {"is_except": True}, {"chek_result": True, "is_useless": False, "is_unregistered": False})

    def get_abnormal_info(self):
        """获取异常的IP信息"""
        useless = self.search_data("公共管理",  {"chek_result": False, "is_useless": True}, {"_id": 0})
        unregistered = self.search_data("公共管理", {"chek_result": False, "is_unregistered": True}, {"_id": 0})
        abnormal_dict = {
            "useless": useless,
            "unregistered": unregistered
        }
        return abnormal_dict

    @staticmethod
    def network_scan_multi(net):
        """结合端口和ping包扫描输出网络占用列表"""
        nmap_scan_port = Scanner(net, scan_type_1, scan_port)
        info1 = nmap_scan_port.scan_discover()
        nmap_scan_ping = Scanner(net, scan_type_2, scan_port)
        info2 = nmap_scan_ping.scan_discover()
        network_info = set(info1['hosts'] + info2['hosts'])
        return network_info

    def network_scan(self, net, env_name):
        """全场景资产扫描，结合端口和ping包扫描输出网络占用列表"""
        nmap_scan_port = Scanner(net, scan_type_1, scan_port)
        print("{} sacan is start".format(env_name))
        info1 = nmap_scan_port.scan_discover()
        nmap_scan_ping = Scanner(net, scan_type_2, scan_port)
        info2 = nmap_scan_ping.scan_discover()
        network_info = set(info1['hosts'] + info2['hosts'])
        self.scan_result[env_name] = network_info
        print("{} sacan is finish".format(env_name))

    def network_scan_threading(self, env_info):
        """
        并发执行全场景扫描
        :param env_info: dict, 全场景信息字典
        :return:
        """
        name_list = [key for key in env_info]
        net_list = [value for key, value in env_info.items()]
        threads = []
        print("开始场景IP信息扫描")
        for i in range(len(net_list)):
            t = Thread(target=self.network_scan, args=(net_list[i], name_list[i]))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def set_all_env_used(self):
        """根据扫描结果设置全场景的资源使用"""
        for key, value in self.scan_result.items():
            # 初始化数据
            self.modify_data(key, {}, {"scan_used": False})
            for ip in value:
                self.modify_data(key, {"ip": ip}, {"scan_used": True})

    def create_net_excel_by_db(self, color, env_info):
        """生成统计表格用于后续检查"""
        wb = xw.Book()
        print("开始生成场景信息表")
        for name, case_net in env_info.items():
            sht = wb.sheets.add(name)
            for i in range(25):
                sht.range('A{}:J{}'.format(i + 1, i + 1)).value = [i * 10 + 1, i * 10 + 2, i * 10 + 3, i * 10 + 4,
                                                                   i * 10 + 5, i * 10 + 6, i * 10 + 7, i * 10 + 8,
                                                                   i * 10 + 9, i * 10 + 10]
            sht.range('A26:D26').value = [251, 252, 253, 254]
            # 数据库中读取扫描数据
            info = self.search_data(name, {"scan_used": True}, {"ip": 1})
            for ip in info:
                ip = ip["ip"]
                num = int(self.make_ip(ip))
                cols = ['J', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I']
                col = cols[num % 10]  # 定位列数
                if not num % 10 == 0:
                    row = num // 10 + 1  # 定位行数
                else:
                    row = num // 10
                locate = col + str(row)
                sht.range(locate).color = color
            if name == "公共管理":
                info = self.search_data(name, {"is_except": True}, {"ip": 1})
                for ip in info:
                    ip = ip["ip"]
                    num = int(self.make_ip(ip))
                    cols = ['J', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I']
                    col = cols[num % 10]  # 定位列数
                    if not num % 10 == 0:
                        row = num // 10 + 1  # 定位行数
                    else:
                        row = num // 10
                    locate = col + str(row)
                    sht.range(locate).color = exception_color

            # 首行添加场景标题
            sht.range("1:1").api.Insert()
            sht.range("A1:J1").merge()
            title = name + " ({})".format(case_net)
            sht.range("A1").value = title
            sht.range("A1").color = (5, 195, 195)
            sht.range("A1").row_height = 30
            sht.range("A1").api.HorizontalAlignment = -4108  # 居中
            sht.range("A1").api.Font.Bold = True  # 粗体
            # 设置边框
            # 标题行
            cell = sht.range("A1")
            # 底边框
            cell.api.Borders(9).LineStyle = 1
            cell.api.Borders(9).weight = 3
            # 左边框
            cell.api.Borders(7).LineStyle = 1
            cell.api.Borders(7).weight = 3
            # 顶边框
            cell.api.Borders(8).LineStyle = 1
            cell.api.Borders(8).weight = 3
            # 右边框
            cell.api.Borders(10).LineStyle = 1
            cell.api.Borders(10).weight = 3

            # 内容行
            cells = sht.range("A2：J27")
            # 底边框
            cells.api.Borders(9).LineStyle = 1
            cells.api.Borders(9).weight = 3
            # 左边框
            cells.api.Borders(7).LineStyle = 1
            cells.api.Borders(7).weight = 3
            # 顶边框
            cells.api.Borders(8).LineStyle = 1
            cells.api.Borders(8).weight = 3
            # 右边框
            cells.api.Borders(10).LineStyle = 1
            cells.api.Borders(10).weight = 3
            # 内部垂直
            cells.api.Borders(11).LineStyle = 1
            cells.api.Borders(11).weight = 1
            # 内部水平
            cells.api.Borders(12).LineStyle = 1
            cells.api.Borders(12).weight = 1
        wb.save(self.path)
        wb.close()

    def set_port_sacn(self, collection, used_list):
        """UP端口信息更新数据库"""
        # 初始化数据，防止历史数据残留
        self.modify_data(collection, {}, {"scan_used": False})
        for port in used_list:
            self.modify_data(collection, {"port": port}, {"scan_used": True})

    def set_port_base(self):
        """设置端口解析"""
        wb = xw.Book(self.port_base_excel)
        sht = wb.sheets.active
        for i in range(3, 60):
            locate1 = "A{}".format(i)
            locate2 = "D{}".format(i)
            if sht.range(locate1).value and sht.range(locate2).value == "Y":
                self.modify_data("管控TOR_240.6", {"port": sht.range(locate1).value}, {"is_used": True})
            locate3 = "F{}".format(i)
            locate4 = "I{}".format(i)
            if sht.range(locate3).value and sht.range(locate4).value == "Y":
                self.modify_data("业务TOR_240.4", {"port": sht.range(locate3).value}, {"is_used": True})
        wb.close()

    def check_port(self):
        """检查公共资源使用情况"""
        collection1 = "管控TOR_240.6"
        collection2 = "业务TOR_240.4"
        # 初始化数据
        self.modify_data(collection1, {}, {"chek_result": True, "is_useless": False, "is_unregistered": False})
        self.modify_data(collection2, {}, {"chek_result": True, "is_useless": False, "is_unregistered": False})
        # 更新数据校验结果
        # 登记未使用
        self.modify_data(collection1, {"is_used": True, "scan_used": False}, {"chek_result": False, "is_useless": True})
        self.modify_data(collection2, {"is_used": True, "scan_used": False}, {"chek_result": False, "is_useless": True})

        # 使用未登记
        self.modify_data(collection1, {"is_used": False, "scan_used": True}, {"chek_result": False, "is_unregistered": True})
        self.modify_data(collection2, {"is_used": False, "scan_used": True}, {"chek_result": False, "is_unregistered": True})

    def create_port_excel(self):
        """生成端口统计表格用于后续检查"""
        wb = xw.Book(self.path)
        sht = wb.sheets.add("GRE TOR接口统计表")
        # print("开始生成端口信息表")
        unregistered_lis = []
        useless_lis = []
        # "管理TOR"
        # 首行添加场景标题
        sht.range("A1:B1").merge()
        title = "管控TOR_240.6"
        sht.range("A1").value = title
        sht.range("A1").color = (5, 195, 195)
        sht.range("A1").row_height = 30
        sht.range("A1").api.HorizontalAlignment = -4108  # 居中
        sht.range("A1").api.Font.Bold = True  # 粗体
        sht.range("A2").value = "本地端口"
        sht.range("B2").value = "使用情况"
        sht.range("B3:B60").api.HorizontalAlignment = -4108  # 居中
        row = 3
        data_lis = self.search_data("管控TOR_240.6")
        for data in data_lis:
            sht.range("A{}".format(row)).value = data["port"]
            if not data['chek_result']:
                if data['is_unregistered']:
                    sht.range("B{}".format(row)).value = "未登记"
                    sht.range("B{}".format(row)).color = (255, 0, 0)
                    unregistered_lis.append("管控TOR_240.6_{}".format(data["port"]))
                elif data['is_useless']:
                    sht.range("B{}".format(row)).value = "登记未使用"
                    sht.range("B{}".format(row)).color = (255, 200, 100)
                    useless_lis.append("管控TOR_240.6_{}".format(data["port"]))
            elif data['is_used']:
                sht.range("B{}".format(row)).value = "Y"
            row += 1

        # "业务TOR"
        # 首行添加场景标题
        sht.range("E1:F1").merge()
        title = "业务TOR_240.4"
        sht.range("E1").value = title
        sht.range("E1").color = (5, 195, 195)
        sht.range("E1").row_height = 30
        sht.range("E1").api.HorizontalAlignment = -4108  # 居中
        sht.range("E1").api.Font.Bold = True  # 粗体
        sht.range("E2").value = "本地端口"
        sht.range("F2").value = "使用情况"
        sht.range("F3:F60").api.HorizontalAlignment = -4108  # 居中
        row = 3
        data_lis = self.search_data("业务TOR_240.4")
        for data in data_lis:
            sht.range("E{}".format(row)).value = data["port"]
            if not data['chek_result']:
                if data['is_unregistered']:
                    sht.range("F{}".format(row)).value = "未登记"
                    sht.range("F{}".format(row)).color = (255, 0, 0)
                    unregistered_lis.append("业务TOR_240.4_{}".format(data["port"]))
                elif data['is_useless']:
                    sht.range("F{}".format(row)).value = "登记未使用"
                    sht.range("F{}".format(row)).color = (255, 200, 100)
                    useless_lis.append("业务TOR_240.4_{}".format(data["port"]))
            elif data['is_used']:
                sht.range("F{}".format(row)).value = "Y"
            row += 1
        wb.save(self.path)
        wb.close()
        return [unregistered_lis, useless_lis]


if __name__ == '__main__':
    m = Data_Analysis("127.0.0.1", "GRE_ENV")
    m.login()
    # m.set_base_used("公共管理")
    # m.set_except_used("公共管理")
    # scan_info = m.network_scan_multi(scan_net)
    # m.set_scan_used("公共管理", scan_info)
    # m.check_ip()

    # m.network_scan_threading(env_dict)
    # print(m.scan_result)
    # m.set_all_env_used()
    # m.create_net_excel_by_db(used_color, env_dict)

    # m.set_port_base()

    # t1 = Port_check(Mgt_access_Switch, Mgt_access_user, Mgt_access_paassword)
    # t1.login()
    # port_lis_up = t1.get_port_up()
    # t1.logout()
    # # 业务TOR接口信息
    # t1 = Port_check(yw_access_Switch, yw_access_user, yw_access_paassword)
    # t1.login()
    # port_lis_up_2 = t1.get_port_up()
    # t1.logout()
    # m.set_port_sacn("管控TOR_240.6", port_lis_up)
    # m.set_port_sacn("业务TOR_240.4", port_lis_up_2)
    #
    # m.check_port()

    m.create_port_excel()
    print([x for x in m.search_data("管控TOR_240.6", {"chek_result": False}, {"_id": 0})])

    m.close()

