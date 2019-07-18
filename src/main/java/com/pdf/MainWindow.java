package com.pdf;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;

import javax.swing.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * 生成密钥的方法
 * keytool -genkey -v -keystore test.p12 -storetype pkcs12 -alias Myapp -keyalg RSA -keysize 2048 -validity 10000
 *
 * 应用到正式的项目中导入进去了6个jar包才可以了
 * bcpkix-jdk15on-1.49.jar
 * bcprov-jdk15on-1.49.jar
 * itextpdf-5.5.9.jar
 * itext-pdfa-5.5.9.jar
 * itext-xtra-5.5.9.jar
 * xmlworker-5.5.9.jar
 *
 *
 */
public class MainWindow {

    public static final String KEYSTORE = "E:\\my\\aa\\test.p12";
    public static final char[] PASSWORD = "123456".toCharArray();//keystory密码
    public static final String SRC = "E:\\my\\aa\\gg.pdf";
    public static final String DEST = "E:\\my\\aa\\dest.pdf";

    public void sign(String src  //需要签章的pdf文件路径
            , String dest  // 签完章的pdf文件路径
            , Certificate[] chain //证书链
            , PrivateKey pk //签名私钥
            , String digestAlgorithm  //摘要算法名称，例如SHA-1
            , String provider  // 密钥算法提供者，可以为null
            , MakeSignature.CryptoStandard subfilter //数字签名格式，itext有2种
            , String reason  //签名的原因，显示在pdf签名属性中，随便填
            , String location) //签名的地点，显示在pdf签名属性中，随便填
            throws GeneralSecurityException, IOException, DocumentException {
        //下边的步骤都是固定的，照着写就行了，没啥要解释的
        // Creating the reader and the stamper，开始pdfreader
        PdfReader reader = new PdfReader(src);
        //目标文件输出流
        FileOutputStream os = new FileOutputStream(dest);
        //创建签章工具PdfStamper ，最后一个boolean参数
        //false的话，pdf文件只允许被签名一次，多次签名，最后一次有效
        //true的话，pdf可以被追加签名，验签工具可以识别出每次签名之后文档是否被修改
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
        // 获取数字签章属性对象，设定数字签章的属性
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
//        appearance.setSignDate(Calendar.getInstance());
        //设置签名的位置，页码，签名域名称，多次追加签名的时候，签名预名称不能一样
        //签名的位置，是图章相对于pdf页面的位置坐标，原点为pdf页面左下角
        //四个参数的分别是，图章左下角x，图章左下角y，图章右上角x，图章右上角y
        //读取图章图片，这个image是itext包的image
        Image image = Image.getInstance("E:\\my\\aa\\gz.png");
//        float width = image.getWidth();
//        float height = image.getHeight();
//        appearance.setVisibleSignature(new Rectangle(400, 400, 400+width, 400+height), 1, "sig1");
        appearance.setVisibleSignature(new Rectangle(200, 200, 300, 300), 1, "sig1");
        appearance.setSignatureGraphic(image);
        appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
//        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        // 这里的itext提供了2个用于签名的接口，可以自己实现，后边着重说这个实现
        // 摘要算法
        ExternalDigest digest = new BouncyCastleDigest();
        // 签名算法
        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, null);
        // 调用itext签名方法完成pdf签章
        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) {
        try {
            //读取keystore ，获得私钥和证书链
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(KEYSTORE), PASSWORD);
            String alias = (String) ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
            Certificate[] chain = ks.getCertificateChain(alias);
            //new一个上边自定义的方法对象，调用签名方法
            MainWindow app = new MainWindow();
            app.sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA1, null, MakeSignature.CryptoStandard.CMS, "pdf", "CN");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            JOptionPane.showMessageDialog(null, e.getMessage());
            e.printStackTrace();
        }
    }


}