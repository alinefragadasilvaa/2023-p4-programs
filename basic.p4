/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t; // endereço mac
typedef bit<32> ip4Addr_t; // endereço ip

header ethernet_t { // camada l2, na mesma rede
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t { // camada l3, redes diferentes
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet, // passando como arugumentos o pacote os cabeçalhos e os metadados
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start { // estados de análise do pacote
        transition parse_ethernet; // indo para parse do cabeçalho ethernet
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet); // extraindo cabeçalho ethernet e armazenando em hdr
        transition select(hdr.ethernet.etherType) { // decidindo a continuação da análise com base na informação do campo ethertype
            TYPE_IPV4: parse_ipv4; // indo para o parse do cabeçalho ipv4
            default: accept; // pacote aceito
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4); // extraindo cabeçalho ipv4 e armazenando em hdr
        transition accept; // pacote aceito
    }

    // cabeçalhos ethernet e ipv4 do pacote de entrada extraídos e armazenados para o processamento
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { // verifica integridade dos dados
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr, //dados que serão usados/editados no processo de ingresso do pacote
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) { // o próximo endereço de destino e a porta de saída são retitados das tabelas 
       standard_metadata.egress_spec = port; // adicionando a porta de saída nos metadados
       hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; // atualizando o endereço mac de origem, o destino atual se torna a origem do próximo salto
       hdr.ethernet.dstAddr = dstAddr; // atualizando o endereço de destino do próximo salto
       hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // algoritmo que decide encaminhamento do pacote com base no endereço de destino
        }
        actions = {
            ipv4_forward; // ações definidas
            drop;
            NoAction;
        }
        size = 1024; // máximo de entradas
        default_action = NoAction(); // ação padrão
    }

    apply { // ações a serem executadas
        if(hdr.ipv4.isValid()){ // aplica a tabela de ações apenas se o cabeçalho for válido
             ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply { // ações a serem executadas
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) { // pacote que será transmitido e cabeçalho processado
    apply { // ações a serem executadas
       packet.emit(hdr.ethernet); // inserindo os cabeçalhos nos pacotes
       packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
