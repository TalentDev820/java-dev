package com.r.crypto.encryption.hibernate;

import com.r.crypto.encryption.hibernate.converter.StringToBytesConverter;
import org.hibernate.type.StringType;

import java.util.Properties;

public class EncryptedStringType extends EncryptedType {
    @Override
    protected void initConfig(Properties parameters) {
        super.initConfig(parameters);
        typeModel.setPlaintextColumnType(StringType.INSTANCE);
        typeModel.setBytesConverter(new StringToBytesConverter());
    }
}
