package dev.xdbe.booking.model.booking;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Autowired;

import dev.xdbe.booking.helper.CryptoHelper;

@Converter
public class CreditCardConverter implements AttributeConverter<String, String> {

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return attribute;
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        // Step 5: Mask credit card number
        // Insert your code here to mask credit card number
        String first = dbData.substring(0, 4);
        String last = dbData.substring(12);

        String stars = "********";

        return first + stars + last;
   }

    
}
