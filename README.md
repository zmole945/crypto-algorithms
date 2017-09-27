
crypto-algorithms
=================

關於
---
這裡整理了一份C語言實現的加密算法，部分來自:
Brad Conte (brad@bradconte.com)
gityf(voipman@sina.cn)

這些算法經過了基本的數據測試可應用於教學演示用途，
進行基本加解密，摘要計算等，或者用於對照算法實現結果。

這些算法未特別的進行時間與空間上的優化，以及健壯性的專門設計，
如果要將其應用于商業用途，還需做相應的工作。

這些算法盡量只使用基本的C庫，避免更多依賴性，以方便移植維護。


編譯
---
這裡包含des、aes、sha1、sha256、sm3、sm4等幾種算法，
可以一次性編譯所有源碼，生成演示文件：
 make all
也可以單獨編譯其中一種，例如編譯sm3演示文件：
 make sm3
清除所有演示程序：
 make clean

源碼帶有doxygen配置文件，可以生成相應doxygen文檔：
 make doxygen
清除doxygen生成文件：
 make doxygen_clean

