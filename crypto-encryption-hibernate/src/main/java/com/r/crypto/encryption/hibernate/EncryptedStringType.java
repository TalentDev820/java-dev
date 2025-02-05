package com.r.crypto.encryption.hibernate;

import com.r.crypto.encryption.hibernate.converter.StringToBytesConverter;
import org.hibernate.type.descriptor.jdbc.VarcharJdbcType;

import java.util.Properties;

public class EncryptedStringType extends EncryptedType {
    @Override
    protected void initConfig(Properties parameters) {
        super.initConfig(parameters);
        typeModel.setPlaintextColumnType(VarcharJdbcType.INSTANCE);
        typeModel.setBytesConverter(new StringToBytesConverter());
    }
}
