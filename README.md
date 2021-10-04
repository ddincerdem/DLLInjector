1.GİRİŞ

DLL Injection, DLL(Dynamic Link Library) Windows işletim sistemlerinde runtime sırasında dahil edilebilir ve içlerinden kod çalıştırılabilir olmasından dolayı manipüle edilerek kodu yaza kişinin, processin kendi isteği doğrultusunda çalışmasını sağlamak amacıyla ortaya çıkmış bir yöntemdir. Bir program LoadLibrary() fonksiyonu ile kendi mimarisiyle (32–64) uyumlu olan herhangi bir DLL’i içerisine yükleyebilir.

2.DLL Nedir?

DLL İngilizce Dynamic Link Library, Türkçe anlamı Dinamik Bağlantı Kütüphanesi’dir. Adı Dynamic Link Library baş harfleri alınarak kısaltılmıştır.
DLL dosyaları görevi çalışan programların ortaklaşa yapmış olduğu işlemleri tek bir dosya içinde yapmak, program çalışma esnasında gerekli olan fonksiyonları kendi içerisinde bulunmaz ise bunu dinamik link kütüphanesi’nde yani DLL dosyasında aramaktadır.
Programlar işlevlerini devam ettirmek için DLL dosyaları içerisinde bulunan işlemlerden yardım alarak çalıştırma bütünlüğü sağlamaktadır. Bir exe dosyası nasıl programın çalışmasında gerekli ise DLL dosyasında aynı şekilde programın çalışmasında gerekli sistem dosyalarıdır.

3.DLL Injection Nedir?

Bir DLL dosyasını bir process’in adres alanı içerisinde çalıştırarak, o process’in çalışmasını manipüle etmek amacıyla kullanılan bir tekniktir.
Böylece, hedef sistem üzerinde özel hazırlanmış bir DLL dosyası aracılığıyla, rastgele komut çalıştırılabilir. DLL Injection saldırılarının çoğu, tersine mühendislik saldırıları için yapılır. Ayrıca, hedef sistem üzerinde hak ve yetki yükseltmek (privilege escalation) amacıyla da bu yönteme başvurulabilir.
Programlar işlevlerini devam ettirmek için DLL dosyaları içerisinde bulunan işlemlerden yardım alarak çalıştırma bütünlüğü sağlamaktadır. Bir exe dosyası nasıl programın çalışmasında gerekli ise DLL dosyasında aynı şekilde programın çalışmasında gerekli sistem dosyalarıdır.

 
4.CreateRemoteThread( )

Bu Injection türünde;
•	Process’e enjekte edilecek olan DLL dosyası hedef sisteme yerleştirilir.
•	Hedef process’in belleği üzerinde DLL dosyasının yolunu tutmak için yer ayrılır.
•	DLL dosyasının bulunduğu dizin yolu, process’in belleğine kopyalanır ve uygun adresler belirlenir.
•	DLL dosyası çalıştırılır ve enjekte edildiği process üzerinden işlerini yürütmeye başlar.

Öncelikle ele alınacak processi seçerek başlıyoruz;
 
Seçeceğimiz bir process’e DLL enjeksiyonu yapabilmek için OpenProcess fonksiyonu ile birlikte; CreateThread, QueryInformation, VMOperation, VMWrite ve VMRead bayrakları kullanılmalıdır.
 
Bu işlemden sonra hedef process’in sanal belleğinde yer ayırmak için VirtualAllocEx() fonksiyonu kullanılır. Bu fonksiyonun parametreleri aracılığı ile hedef process, ayrılacak bellek adresinin başlangıç adresi,bellek alanı uzunluğu, bellek ayırma türü ve ayrılacak alan için bellek izinleri belirtilir.
  
Hedef process’te ayırdığımız sanal bellek alanına DLL dosyasının path’ini WriteProcessMemory() fonksiyonu ile enjekte edebiliriz.
 
Bir DLL dosyasını process belleğine yüklemek için LoadLibraryA fonksiyonu kullanılır. LoadLibraryA, kernel32.dll üzerinden çağrılabilir. Bunun için GetProcAddress() fonksiyonu kullanılır. Bu fonksiyon, belirtilen bir kütüphane üzerinden, bir fonksiyon veya bir değişkenin adresini almak amacıyla kullanılır.
CreateRemoteThread fonksiyonu, bir process’in sanal bellek alanında thread oluşturur. Bu fonksiyon kullanılarak LoadLibraryA fonksiyonu, process’in ayrılan sanal bellek alanında bir thread olarak çalıştırılır. Böylece DLL Injection işlemi tamamlanır.
 
‎CreateRemoteThread işlevini kullanarak processin adres alanına nasıl DLL ekleyebileceğimizi gördük. Saldırgan, process/user hakkında yararlı bilgiler toplamak üzere belirli bir işlevi, işlemin IAT alma tablosuna bağlamak için bu yöntemi kullanabilir.

 
