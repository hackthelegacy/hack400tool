//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2017  Bart Kulach
//    This file, IBMiUtilities.java, is part of hack400tool package.

//    "hack400tool" is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.

//    "hack400tool" is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.

//   You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
package org.hackthelegacy.hack400tool.ibmiscannercore;

import com.ibm.as400.access.AS400DataType;
import com.ibm.as400.access.AS400Message;
import com.ibm.as400.access.AS400Text;
import java.io.File;
import java.io.IOException;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import javax.swing.table.DefaultTableModel;

public final class IBMiUtilities {

    private IBMiUtilities(){
    }

    public static void prepareFile(String fileName) throws IOException {
        File workFile = new File(fileName);
        if (!workFile.exists()) {
            workFile.getParentFile().mkdirs();
            workFile.createNewFile();
        }        
    }    
    
    public static String convertLongTimeToString(long time){
        Date date = new Date(time);
        Format format = new SimpleDateFormat("yyyy MM dd HH:mm:ss");
        return format.format(date);
    }
    
    
    public static String stringFromAS400Message(AS400Message[] message){
        String outputString = "";
        if (message.length == 0) return "";
        for (int i=0; i<message.length; i++)
            outputString += message[i].getText() + "\n" + message[i].getHelp() + "\n";
        return outputString;
    }
    
    
    public static String padTrimString(String inputString, int len){
        String outputString = inputString;
        if (outputString.length() > len)
            return outputString.substring(0, len-1);
        
        while (outputString.length() < len)
            outputString += " ";
        
        return outputString;
    }    
    
    public static String stringFromArray(String[] stringArray, String separator) {
        if (stringArray.length == 0) return "";
        String outputString = "";
        Arrays.sort(stringArray);
        for (String stringElement : stringArray){
            outputString += (outputString == "" ? "" : separator) + stringElement.trim();
        }
        return outputString;
    }
    
    
    public static String[] arrayFromString(String inputString, String separator) {
        if (inputString.length() == 0) return null;
        return inputString.split(separator);
    }

    public static String[] arrayFromDataTableModel(DefaultTableModel tableModel) {
        if (tableModel.getColumnCount() > 1 || tableModel.getRowCount() == 0)
            return null;
        
        String[] outputArray = new String[tableModel.getRowCount()];
        
        for (int i=0;i<tableModel.getRowCount(); i++)
            outputArray[i] = tableModel.getValueAt(i, 0).toString();
        return outputArray;
    }
    
    public static String hexStringFromEBCDIC(byte[] inputString){

        if (inputString.length == 0) return "";
        
        char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
        char[] outputChars = new char[2 * inputString.length];
        for (int i = 0; i < inputString.length; ++i)
        {
            outputChars[2 * i] = HEX_CHARS[(inputString[i] & 0xF0) >>> 4];
            outputChars[2 * i + 1] = HEX_CHARS[inputString[i] & 0x0F];
        }
        return new String(outputChars);
    }    

    
    public static int sumDataTypeFields(AS400DataType[] dataTypeArray) {
        if (dataTypeArray.length == 0)
            return 0;
    
        int dataTypeSum = 0;
        
        for (AS400DataType arrayElement : dataTypeArray)
            dataTypeSum += arrayElement.getByteLength();
        
        return dataTypeSum;
    }    
    
    public int sumBytes(byte[] byteArray) {
        if (byteArray.length == 0)
            return 0;
    
        int byteSum = 0;
        
        for (byte arrayElement : byteArray)
            byteSum += arrayElement;
        
        return byteSum;
    }
    
    public static String padTextRight(String inputText, int length)
    {
        if (inputText.length() > length) {
            return inputText.substring(0, length);
        }
        
        String outputText = inputText;
        while (outputText.length() < length) {
            outputText += " ";
        }
        return outputText;
    }
    
    
    public byte[] _convertToArgv(String[] paramStrings){
        
        int totalLength = 0;
        for (String param : paramStrings)
            totalLength += param.length();  
        
        totalLength += paramStrings.length; //add space for \0 * number of params
        
        byte [] outputBuf = new byte[totalLength];
        
        int offset = 0;
        
        for (String param : paramStrings) {
            //Convert with CCSID 819 (default PASE ASCII CCSID, ISO 8859-1 equivalent)
            (new AS400Text(param.length() + 1, 819)).toBytes(
                                        param + new String(new byte[] {0x00}), outputBuf, offset);
            offset += param.length() + 1;
        }
        
        return outputBuf;
    }    
}
