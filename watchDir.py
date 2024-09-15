import os



def getDirSize(directory="./"):
    '''
    Sums Directory Size
    Return:
        - *int, Directory Size In Bytes
    '''
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            if os.path.isfile(file_path):
                total_size += os.path.getsize(file_path)
    return total_size
