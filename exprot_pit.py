from netzob.all import *
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement
from xml.etree.ElementTree import ElementTree

class PitConver:
    def __init__(self, proto_Obj = Symbol):

        self.proto_Obj = proto_Obj;
        self.no_num = 0
        self.no_raw = 0
        self.no_field = 0

        self.all_field = []  
        self.all_block = []  
        self.all_father = []  

        self.all_relation = []
        self.all_rel_block = []

        self.all_new_block = []

        self.pit = self.get_pit_obj()
        #self.state_machine = state_machine;
    '''
    -----------------------------------------------------------------
        the fowllowing is to covert basic netzob datatype to xml(.pit) node
        - interger->number
        - raw, hexastring, bitarray->blog 
        - string->string 
        - waiting to do->timestape
        - waiting to do->ipv4

    '''
    def __convert_number(self, fa_node, integer: Integer, name = None):
        # pit: number
        # netzob: interger
        num_node = SubElement(fa_node, "Number")
        if name == None:
            name = "num"+str(self.no_num)
            self.no_num+=1
        num_node.set("name", name)
        num_node.attrib["size"] = str(integer.unitSize.value)
        if integer.sign == Sign.UNSIGNED:
            num_node.set("signed", "false")
        if integer.endianness == Endianness.BIG:
            num_node.set("endian", "big")
        if integer.value != None:
            num_node.set("value", str(int(integer.value.to01(), base=2)))
        
        return num_node
    
    def __convert_raw(self, fa_node, raw: Raw or HexaString or BitArray, name = None):
        # pit: blog
        # netzob: raw, hexastring, BitArray
        raw_node = SubElement(fa_node, "Blob")
        if name == None:
            name = 'raw'+str(self.no_raw)
            self.no_raw+=1
        (min_s, max_s) = raw.size
        if min_s == max_s:
            raw_node.set("length", str(min_s//8))
        raw_node.set("valueType", "hex")
        if raw.value != None:
            value_con = ""
            hex_str = raw.value.tobytes().hex().upper()
            for i in range(hex_str):
                value_con += hex_str[i]
                if i % 2 == 1:
                    value_con += " "
            if value_con[-1] == " ":
                value_con = value_con[0:-1]
            raw_node.set("value", value_con)
        
        return raw_node
                
    def __convert_string(self, fa_node, string: String, name = None):
        # pit: string
        # netzob: string
        str_node = SubElement(fa_node, "String")
        if name != None:
            str_node.set("name", name)
        (min_s, max_s) = string.size
        if min_s == max_s:
            str_node.set("length", str(min_s//8))
        if string.encoding[0:2].lower() == "utf":
            str_node.set("type", "utf"+string.encoding[4::])
        if string.value != None:
            str_node.set("value", string.value.tobytes().decode())

        return str_node
    
    def __convert_timestape():
        pass

    def __convert_ipv4():
        pass


    '''
    -------------------------------------------------------------------------
    the following is to convert composite netzob obj to xml(.pit) node
        - Aggregate
        - Alternate
        - Repeat
        - Optional 
    '''
    def __convert_aggregate(self, fa_node, agg: Agg, name = None):
        block = SubElement(fa_node, "Block")
        if name != None:
            block.set("name", name)
        for child_node in agg.children:
            self.__select_node_type(block, child_node, None)
    
    def __convert_alternate(self, fa_node, alt: Alt, name = None):
        choice = SubElement(fa_node, "Choice")
        if name != None:
            choice.set("name", name)
        for child_node in alt.children:
            self.__select_node_type(choice, child_node, None)
    
    def __convert_repeat(self, fa_node, rep: Repeat, name = None):
        block = SubElement(fa_node, "Block")
        if name != None:
            block.set("name", name)
        (min_s, max_s) = rep.nbRepeat
        for i in range(min_s):
            self.__select_node_type(block, rep.children[0], None)
    
    def __convert_option(self, fa_node, opt: Opt, name = None):
        choice = SubElement(fa_node, "Choice")
        if name != None:
            choice.set("name", name)
        self.__select_node_type(choice, opt.children[0], None)
        SubElement(choice, "Block")

    '''
    ------------------------------------------------------------------------
    the following is to convert relationship
    '''


    def __locate_node(self, targets):
        if len(targets) == 1:
            idx = self.all_field.index(targets[0])
            return self.all_block[idx]
        else:
            idx = []
            is_fa_equ = True
            last_fa = None
            for target in targets:
                idx.append(self.all_field.index(target))
                if last_fa == None:
                    last_fa = self.all_father[idx[0]]
                if self.all_father[idx[-1]] != last_fa:
                    is_fa_equ == False
            if is_fa_equ and len(self.all_father[idx[0]]) == len(targets):
                return self.all_father[idx[0]]
            elif is_fa_equ:
                (bo_node, type_flag) = self.__check_child_node(self.all_father[idx[0]], idx)
                if type_flag == 1:
                    return self.all_father[idx[0]]
                elif type_flag == 2:
                    return bo_node
                else:
                    return None
                '''
                begin_idx = None
                end_idx = None
                at_block = False
                i = 0
                
                for child in self.all_father[idx[0]]: 
                    block_is_ok = False
                    if child not in self.all_block:
                        self.__check_child_node(child, idx)
                        block_is_ok = True
                    if block_is_ok or self.all_block.index(child) in idx:
                        if begin_idx == None:
                            begin_idx = i
                            at_block = True
                        end_idx = i
                        if begin_idx != None and at_block == False:
                            return None
                    else:
                        at_block = False
                    i+=1
                block = Element("Block")
                block.set("name", "block"+str(self.no_field))
                self.no_field+=1
                for child_idx in range(begin_idx, end_idx+1):
                    tmp_node = self.all_father[idx[0]]
                    tmp_child_node = tmp_node[child_idx]
                    tmp_node.remove(tmp_child_node)
                    block.append(tmp_child_node)
                self.all_father[idx[0]].insert(child_idx, block)
                return block
                '''
        return None
    
    def __check_child_node(self, node, idx):
        # 1, all is in
        # 2, some is in
        # 3, not in 
        # 4, none
        begin_idx = None
        end_idx = None
        at_block = False
        i2 = 0
        for child in node:
            if child not in self.all_block and child in self.all_new_block:
                (locate_node, type_num) = self.__check_child_node(child, idx)
                if type_num == 2 and begin_idx==None:
                    return (locate_node,2)
                elif type_num == 2:
                    return (None, 4)
                elif type_num == 4:
                    return (None, 4)
                elif type_num == 1:
                    if begin_idx == None:
                        begin_idx = i2
                        at_block = True
                    end_idx = i2
                    if begin_idx != None and at_block == False:
                        return (None, 4)
                else:
                    at_block = False
            else:
                print(self.all_block.index(child))
                m = self.all_block
                if self.all_block.index(child) in idx:

                    if begin_idx == None:
                        begin_idx = i2
                        at_block = True
                    end_idx = i2
                    if begin_idx != None and at_block == False:
                        return (None, 4)
                else:
                    at_block = False
            i2+=1

        if begin_idx == end_idx == None:
            return (None, 3)
        if begin_idx == 0 and end_idx == len(node)-1:
            return (node, 1)
        block = Element("Block")
        block.set("name", "block"+str(self.no_field)+"checkifnew")
        self.no_field+=1
        for counter in range(begin_idx, end_idx+1):
            tmp_child_node = node[begin_idx]
            node.remove(tmp_child_node)
            block.append(tmp_child_node)
        self.all_father[idx[0]].insert(begin_idx, block)
        self.all_new_block.append(block)
        return (block, 2)
        

    def __convert_value(self, fa_node, value_obj: Value, name = None):
        block = SubElement(fa_node, "Fixup")
        self.all_relation.append(value_obj)
        self.all_rel_block.append(block)
    
    def __process_value(self, value_obj: Value, block):
        target_node = self.__locate_node(value_obj.targets)
        block.set("type", "CopyValueFixup")
        if target_node != None:
            block.set("of", target_node.attrib["name"])
        else:
            print("can't process target of Value type:")
            print(value_obj)
            raise Exception

    def __convert_size(self, fa_node, size_obj: Size, name = None):
        num = SubElement(fa_node, "Number")
        num.set("signed", "false")
        self.all_relation.append(size_obj)
        self.all_rel_block.append(num)
    
    def __process_size(self, size_obj: Size, block):
        target_node = self.__locate_node(size_obj.targets)
        size_rel_block = SubElement(block, "Relation")
        size_rel_block.set("type", "size")
        if target_node != None:
            block.set("of", target_node.attrib["name"])
        else:
            print("can't process target of Size type:")
            print(size_obj)
            raise Exception

    def __convert_padding(self, fa_node, padding_obj: Padding, name = None):
        pad = SubElement(fa_node, "Padding")
        self.all_relation.append(padding_obj)
        self.all_rel_block.append(pad)
    
    def __process_padding(self, pad_obj: Padding, padding):
        target_node = self.__locate_node(pad_obj.targets)
        if target_node != None:
            padding.set("alignment", str(int((pad_obj.modulo-pad_obj.offset)/pad_obj.factor//8)))
            #padding.set("alignedTo", )
        else:
            print("can't process target of Padding type:")
            print(pad_obj)
    
    def __convert_fixup(self, fa_node, fixup_obj, name = None ):
        fixup = SubElement(fa_node, "Fixup")
        self.all_relation.append(fixup_obj) 
        self.all_rel_block.append(fixup)

    def __process_fixup(self, fixup_obj, fixup_block):
        target_node = self.__locate_node(fixup_obj.targets)
        if target_node != None:
            if isinstance(fixup_obj, CRC32):
                fixup_block.set("type", "Crc32Fixup")
            elif isinstance(fixup_obj, InternetChecksum):
                fixup_block.set("type", "IcmpChecksumFixup")
            elif isinstance(fixup_obj, MD5):
                fixup_block.set("type", "MD5Fixup")
            elif isinstance(fixup_obj, SHA1):
                fixup_block.set("type", "SHA1Fixup")
            elif isinstance(fixup_obj, SHA2_224):
                fixup_block.set("type", "SHA224Fixup")
            elif isinstance(fixup_obj, SHA2_256):
                fixup_block.set("type", "SHA256Fixup")
            elif isinstance(fixup_obj, SHA2_384):
                fixup_block.set("type", "SHA384Fixup")
            elif isinstance(fixup_obj, SHA2_512):
                fixup_block.set("type", "SHA512Fixup")
            else:
                print("such fixup can't be transe to PIT node:")
                print(type(fixup_obj))
                raise Exception
            fixup_block.set("of", target_node.attrib["name"])
        else:
            print("can't process target of fixup type:")
            print(fixup_obj)
            raise Exception



    def __process_relation(self):
        for i in range(len(self.all_relation)):
            if isinstance(self.all_relation[i], Size):
                self.__process_value(self.all_relation[i], self.all_rel_block[i])
            elif isinstance(self.all_relation[i], Size):
                self.__process_size(self.all_relation[i], self.all_rel_block[i])
            elif isinstance(self.all_relation[i], Padding):
                self.__process_padding(self.all_relation[i], self.all_rel_block[i])
            else:
                self.__process_fixup(self.all_relation[i], self.all_rel_block[i])

                  
    '''
    -------------------------------------------------------------------------
    the following is to process field node of netzob
    '''
    def __generate_basic_frame(self):
        peach_node = Element('Peach');
        (peach_node.attrib)['xmlns'] = "http://peachfuzzer.com/2012/Peach" 
        (peach_node.attrib)["xmlns:xsi"] = "http://www.w3.org/2001/XMLSchema-instance"
        (peach_node.attrib)["xsi:schemaLocation"] =  "http://peachfuzzer.com/2012/Peach ../peach.xsd"
        return peach_node;

    def __select_node_type(self, fa_node, node, tmp_name = None):
        # generate field_node, (block of peach)
        if isinstance(node, Data):        
            tmp_obj = node.dataType
            if isinstance(tmp_obj, Integer):
                self.__convert_number(fa_node, tmp_obj, tmp_name)
            elif isinstance(tmp_obj, Raw):
                self.__convert_raw(fa_node, tmp_obj, tmp_name)
            elif isinstance(tmp_obj, String):
                self.__convert_string(fa_node, tmp_obj, tmp_name)
        elif isinstance(node, Agg):
            self.__convert_aggregate(fa_node, node, None)
        elif isinstance(node, Alt):
            self.__convert_alternate(fa_node, node, None)
        elif isinstance(node, Repeat):
            self.__convert_repeat(fa_node, node, None)
        elif isinstance(node, Opt):
            self.__convert_option(fa_node, node, None)
        elif isinstance(node, Value):
            self.__convert_value(fa_node, node, None)
        elif isinstance(node, Size):
            self.__convert_size(fa_node, node, None)
        elif isinstance(node, Padding):
            self.__convert_padding(fa_node, node, None)
        else:
            self.__convert_fixup(fa_node, node, None)

    def __convert_field(self, fa_node, node: Field):
        block = SubElement(fa_node, "Block")
        if node.name == "Field":
            block.set("name", "field"+str(self.no_field))
            self.no_field+=1
        else:
            block.set("name", node.name)

        self.all_block.append(block)
        self.all_field.append(node)
        self.all_father.append(fa_node)
        
        if len(node.fields) != 0:
            for sub_field in node.fields:
                self.__convert_field(self, block)
        else:
            self.__select_node_type(block, node.domain)  

    def __generate_data_model(self, peach_node):
        data_model = SubElement(peach_node, 'DataModel')
        data_model.set('name', self.proto_Obj.name)
        
        for sub_field in self.proto_Obj.fields:
            self.__convert_field(data_model, sub_field)

        return peach_node
        
    def get_pit_obj(self):
        peach_node = self.__generate_basic_frame()
        peach_node =  self.__generate_data_model(peach_node)
        self.__process_relation()

        return peach_node
