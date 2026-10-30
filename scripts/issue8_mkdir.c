/* Fixture generation only: operate on one newly generated test image. */
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/unistr.h>
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 ntfs_volume *v=ntfs_mount(argv[1],NTFS_MNT_NONE);
 if(!v){perror("fixture mount");return 3;}
 ntfs_inode *root=ntfs_pathname_to_inode(v,NULL,"/");
 ntfschar name[]={cpu_to_le16('n'),cpu_to_le16('e'),cpu_to_le16('s'),cpu_to_le16('t'),cpu_to_le16('e'),cpu_to_le16('d')};
 ntfs_inode *dir=ntfs_create(root,0,name,6,S_IFDIR);
 if(!dir){perror("fixture mkdir");return 4;}
 ntfs_inode_close(dir);ntfs_inode_close(root);return ntfs_umount(v,0);
}
