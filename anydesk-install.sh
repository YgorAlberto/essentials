sudo wget -qO - https://keys.anydesk.com/repos/DEB-GPG-KEY | apt-key add -
sudo echo "deb http://deb.anydesk.com/ all main" > /etc/apt/sources.list.d/anydesk-stable.list
sudo apt update
wget "http://ftp.us.debian.org/debian/pool/main/libw/libwebp/libwebp6_0.6.1-2+deb10u1_amd64.deb"
wget "http://ftp.us.debian.org/debian/pool/main/g/gtkglext/libgtkglext1_1.2.0-11_amd64.deb"
wget "http://ftp.us.debian.org/debian/pool/main/g/gtk+2.0/libgtk2.0-0t64_2.24.33-6_amd64.deb"
wget "http://ftp.us.debian.org/debian/pool/main/p/pangox-compat/libpangox-1.0-0_0.0.2-5+b2_amd64.deb"
wget "http://ftp.us.debian.org/debian/pool/main/t/tiff/libtiff5_4.1.0+git191117-2~deb10u4_amd64.deb"
 
echo " "
echo "INSTALANDO LIB-WEBP"
echo " "
 
sudo dpkg -i libwebp6_0.6.1-2+deb10u1_amd64.deb
 
echo " "
echo "INSTALANDO LIB-TIFF"
echo " "
 
 
sudo dpkg -i libtiff5_4.1.0+git191117-2~deb10u4_amd64.deb
 
echo " "
echo "INSTALANDO LIB-PANGOX"
echo " "
 
 
sudo dpkg -i libpangox-1.0-0_0.0.2-5+b2_amd64.deb
 
echo " "
echo "INSTALANDO LIB-GTK2"
echo " "
 
sudo dpkg -i libgtk2.0-0t64_2.24.33-6_amd64.deb
 
echo " "
echo "INSTALANDO LIB-GTK"
echo " "
 
 
sudo dpkg -i libgtkglext1_1.2.0-11_amd64.deb
 
echo " "
echo "FINALIZADO AS LIBS"
echo " "

echo " "
echo "INSTALANDO O ANYDESK"
echo " "

#EDIT LATER TO INSTALL .DEB
#wget https://download.anydesk.com/linux/anydesk-latest-amd64.tar.gz
#tar -vzxf anydesk-latest-amd64.tar.gz

sudo apt install anydesk
rm lib*
sudo apt --fix-broken install -y
