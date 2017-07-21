//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2017  Bart Kulach
//    This file, TextAreaOutputStream.java, is part of hack400tool package.

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
package org.hackthelegacy.hack400tool.ibmiscannergui;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public class TextAreaOutputStream extends OutputStream {

   private final JTextArea textArea;
   private final StringBuilder sb = new StringBuilder();
   private String title;
   private FileOutputStream fileOutStream;

   public TextAreaOutputStream(final JTextArea textArea, String title, String fileName) throws FileNotFoundException, IOException {
      this.textArea = textArea;
      this.title = title;
      File outFile = new File(fileName);
      if (!outFile.exists()) {
          outFile.getParentFile().mkdirs();
          outFile.createNewFile();
      }
      fileOutStream = new FileOutputStream(fileName);
      if (!title.isEmpty())
        sb.append(title + "> ");      
   }

   @Override
   public void flush() {
   }

   @Override
   public void close() throws IOException {
    fileOutStream.close();
   }

   @Override
   public void write(int b) throws IOException {

      if (b == '\r')
         return;

      fileOutStream.write(b);      
      
      if (b == '\n') {
         final String text = sb.toString() + "\n";
         SwingUtilities.invokeLater(new Runnable() {
            public void run() {
               textArea.append(text);
            }
         });
         sb.setLength(0);
         if (!title.isEmpty())
             sb.append(title + "> ");

         return;
      }

      sb.append((char) b);      
   }
}
