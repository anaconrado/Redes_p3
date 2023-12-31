import ipaddress
from grader.iputils import *


class IP:

    cur_identification = 0

    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador

            # decrementando o ttl
            ttl = ttl - 1
            version = 4          
            ihl = 5        
            total_length = ihl * 4 + len(payload)   
            my_src_addr = ipaddress.IPv4Address(src_addr)
            my_dst_addr = ipaddress.IPv4Address(dst_addr)

            if ttl == 0:
                
                prev_hop = self._next_hop(src_addr)

                # Reformulando o header IP
                protocolo = 1
                my_src_addr = ipaddress.IPv4Address(self.meu_endereco)
                my_dst_addr = ipaddress.IPv4Address(src_addr)

                ip_header_valores = (
                    (version << 4) + ihl,
                    (dscp << 2) + ecn,
                    48,
                    identification,                     
                    (flags << 13) + frag_offset,               
                    64,
                    protocolo,
                    0,                     
                    int(my_src_addr),  
                    int(my_dst_addr),       
                )
                packed_ip_header = struct.pack("!BBHHHBBHII", *ip_header_valores)

                # recalculando o checksum
                ip_checksum = calc_checksum(packed_ip_header)

                ip_header_valores = ip_header_valores[:7] + (ip_checksum,) + ip_header_valores[8:]

                packed_ip_header = struct.pack("!BBHHHBBHII", *ip_header_valores)

                # Formulando o cabeçalho ICMP
                type = 11  
                code = 0   

                icmp_header_valores = (
                    type,
                    code,
                    0, 
                    0,
                    0,                                     
                )

                packed_icmp_header = struct.pack('!BBHHH', *icmp_header_valores)  

                # calculando o checksum do ICMP
                icmp_checksum = calc_checksum(packed_icmp_header + packed_ip_header)
                icmp_header_valores = (
                    type, 
                    code, 
                    icmp_checksum, 
                    0, 
                    0, 
                )
                #icmp_header_valores = icmp_header_valores[:2] + (icmp_checksum,) + icmp_header_valores[3:]

                # Repack the ICMP header with the correct checksum
                icmp_header = struct.pack('!BBHHH', *icmp_header_valores)

                datagrama = packed_ip_header + icmp_header + datagrama[:28]

                self.enlace.enviar(datagrama, prev_hop)
                return

            else:       
                next_hop = self._next_hop(dst_addr)

                ip_header_valores = (
                    (version << 4) + ihl,
                    0,
                    total_length,
                    identification,                     
                    0,               
                    ttl,
                    proto,
                    0,                     
                    int(my_src_addr),  
                    int(my_dst_addr),       
                )

                packed_ip_header = struct.pack("!BBHHHBBHII", *ip_header_valores)

                # recaluclando o checksum
                checksum = calc_checksum(packed_ip_header)

                ip_header_valores = ip_header_valores[:7] + (checksum,) + ip_header_valores[8:]

                packed_ip_header = struct.pack("!BBHHHBBHII", *ip_header_valores)

                datagrama = packed_ip_header + payload

                self.enlace.enviar(datagrama, next_hop)

            

    def _next_hop(self, dest_addr):

        ip_address = ipaddress.ip_address(dest_addr)
        max_n = None

        for cird, next_hop in self.tabela:
            ip_network = ipaddress.ip_network(cird)

            if ip_address in ip_network:
                if max_n is None or ip_network.prefixlen > max_n[0].prefixlen:
                    max_n = (ip_network, next_hop)

        if max_n:
            return max_n[1]

    
    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        if next_hop is None:
            return
        
        ip_address = ipaddress.IPv4Address(dest_addr)

        version = 4          
        # tamanho do header (20) dividido por quantidade de bits do ihl (4)
        ihl = 5              
        header_length = ihl * 4
        total_length = header_length + len(segmento)
        # Incrementando o identificador e tirando o modulo de 65536 para que não passe de 16 bits
        IP.cur_identification = (IP.cur_identification + 1) % 65536
        flags = 0
        fragment_offset = 0
        # ttl = 64 padrão linux
        ttl = 64             
        # protocolo = 6 padrão tcp
        protocol = 6          
        meu_endereco_ip = ipaddress.IPv4Address(self.meu_endereco)

        # Create the IP header (20 bytes for the IPv4 header without options)
        ip_header = (
            (version << 4) + ihl,
            0,                     
            total_length,
            IP.cur_identification,                     
            0,               
            ttl,
            protocol,
            0,                     
            int(meu_endereco_ip),  
            int(ip_address),           
        )

        packed_ip_header = struct.pack("!BBHHHBBHII", *ip_header)

        checksum = calc_checksum(packed_ip_header)
        ip_header = ip_header[:7] + (checksum,) + ip_header[8:]

        packed_ip_header = struct.pack("!BBHHHBBHII", *ip_header)

        datagrama = packed_ip_header + segmento

        self.enlace.enviar(datagrama, next_hop)
