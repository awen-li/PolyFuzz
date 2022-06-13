import os, tarfile

def make_targz(output_filename, source_dir):
    """
    一次性打包目录为tar.gz
    :param output_filename: 压缩文件名
    :param source_dir: 需要打包的目录
    :return: bool
    """
    try:
        with tarfile.open(output_filename, "w:gz") as tar:
            tar.add(source_dir, arcname=os.path.basename(source_dir))

        return True
    except Exception as e:
        print(e)
        return False

file_main_name = "Seeds.txt"
f = open(file_main_name,"r")
os.makedirs("seeds_corpus")
    
for i in range(1,2):
    file_name = "Seeds_" + str(i)
    file_content = f.readline()

    with open("seeds_corpus/" + file_name + ".bin" , "wb") as f_write:
        f_write.write(str.encode(file_content))
        #f_write.write(bytes(file_content,encoding="ascii"))
        f_write.close()

f.close()

make_targz('seeds_corpus.tar.gz','seeds_corpus/')
        