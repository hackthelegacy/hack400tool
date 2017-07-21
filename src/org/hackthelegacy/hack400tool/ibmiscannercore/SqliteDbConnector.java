//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2017  Bart Kulach
//    This file, SqliteDbConnector.java, is part of hack400tool package.

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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.*;
import java.text.SimpleDateFormat;
import javax.swing.DefaultListModel;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.table.DefaultTableModel;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.apache.poi.xwpf.usermodel.XWPFRun;

public class SqliteDbConnector {

    private Connection dbConnection = null;
    private String databaseName = "";
    

    public SqliteDbConnector(String dbName, boolean deleteOnExit){
        try{
            Class.forName("org.sqlite.JDBC");
            dbConnection = DriverManager.getConnection("jdbc:sqlite:"+dbName);
            databaseName = dbName;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        if (deleteOnExit)
            deleteDatabase(true);
    }
    
    public SqliteDbConnector(String dbName){
        this(dbName, false);
    }    

    public String getDatabaseFileName(){
        return databaseName;
    }
    
    public void deleteDatabase()
    {
        deleteDatabase(false);
    }
    
    public void deleteDatabase(boolean deleteOnExit)
    {
        File jarFile = new File(SqliteDbConnector.class.getProtectionDomain().getCodeSource().getLocation().getPath());
        String jarPath = jarFile.getParentFile().getPath();
        File dbFile = new File(jarPath + File.separator + databaseName);
        if (deleteOnExit)
            dbFile.deleteOnExit();
        else
            dbFile.delete();        
    }
    
    public void disconnect() throws SQLException
    {
        //dbConnection.commit();
        dbConnection.close();
    }
    
    public void insertrow(String tableName, Vector values) throws SQLException
    {
        String queryString = "INSERT INTO " + tableName.replaceAll("[^A-Za-z0-9]", "") + " VALUES("; 
        for (Object value : values)
            //queryString += "\"" + String.valueOf(value).replaceAll("[^A-Za-z0-9\\-\\ \\.\\,\\(\\)\\[\\]\\*\\#\\_\\$\\/\\@]", "") + "\", ";
            queryString += "\"" + String.valueOf(value).replaceAll("[\"\']", "") + "\", ";
        
        queryString = queryString.substring(0,queryString.length()-2) + ");";
        this.query(queryString);
    }
    
    public String unionTempTables(String[] tableNames) throws SQLException {
        String realTableName = "unionTemp" + (new SimpleDateFormat("YYMMddHHmmSS").format(new java.util.Date()));

        String queryString = "CREATE VIEW " + realTableName + " AS ";
        for (int i=0; i<tableNames.length;i++)
            queryString += "SELECT * FROM "  + tableNames[i] + (i != tableNames.length - 1 ? " UNION ALL " : ";");            
        this.query(queryString);
        return realTableName;
    }

    public String createTempTable(String tableName, String[] colNames) throws SQLException {
        String realTableName = tableName + (new SimpleDateFormat("YYMMddHHmmSS").format(new java.util.Date()));
        String queryString = "CREATE TABLE " + realTableName + "(";
        for (int i=0; i<colNames.length;i++)
            queryString += colNames[i] + " VARCHAR" + (i != colNames.length - 1 ? ", " : ");");        
        this.query(queryString);
        return realTableName;
    }
    
    public String createTempTable(String tableName, int colNumber) throws SQLException {
        String realTableName = tableName + (new SimpleDateFormat("YYMMddHHmmSS").format(new java.util.Date()));
        String queryString = "CREATE TABLE " + realTableName + "(_0 VARCHAR";
        for (int i=1; i<colNumber;i++)
            queryString += ", _"  + String.valueOf(i) + " VARCHAR";        
        queryString += ");";
        this.query(queryString);
        return realTableName;
    }
    

    private void prepareFile(String fileName) throws IOException {
        File workFile = new File(fileName);
        if (!workFile.exists()) {
            workFile.getParentFile().mkdirs();
            workFile.createNewFile();
        }        
    }
    
    public void exportXLSX(String fileName, String tableName) throws SQLException
    {        
        this.query("SELECT * FROM " + tableName.replaceAll("[^A-Za-z0-9]", "") + ";").toXLSX(fileName);
    }

    public void exportDOCX(String fileName, String tableName) throws SQLException
    {        
        this.query("SELECT _1 FROM " + tableName.replaceAll("[^A-Za-z0-9]", "") + ";").toDOCX(fileName);
    }

    public Query query(String queryString) throws SQLException {
        return new Query(queryString);
    }
    
    public Query query(String queryString, String[] filterParam) throws SQLException {
        return new Query(queryString, filterParam);
    }
    
    public class Query {

        private PreparedStatement statement = null;
        public ResultSet resultSet = null;
        
        Query(String queryString) throws SQLException {
            this(queryString, null);
        }
        
        Query(String queryString, String[] filterParam) throws SQLException {
            String tmpQuery;
            
            if (queryString.toUpperCase().startsWith("SELECT") ||
                queryString.toUpperCase().startsWith("CREATE") ||    
                queryString.toUpperCase().startsWith("INSERT") ||
                queryString.toUpperCase().startsWith("UPDATE") ||
                queryString.toUpperCase().startsWith("DELETE")) {
                statement = dbConnection.prepareStatement(queryString);
                if (filterParam != null)
                    for (int i=0; i<filterParam.length; i++)
                        statement.setString(i+1, filterParam[i]);
                if (statement.execute())
                    resultSet = statement.getResultSet();
            } else {
                statement = dbConnection.prepareStatement(
                        "SELECT sqlcommand FROM sqlcommands WHERE id = ? LIMIT 1;");
                statement.setString(1, queryString);
                resultSet = statement.executeQuery();                
                if (resultSet != null) {
                    tmpQuery = resultSet.getString(1);
                    statement = dbConnection.prepareStatement(tmpQuery);
                    resultSet = statement.executeQuery();
                }
            }                    
        }               
        
        public DefaultTableModel toTableModel() throws SQLException {

            if (resultSet == null || dbConnection == null) 
                return null;
            
            ResultSetMetaData metaData = resultSet.getMetaData();
            int numberOfColumns = metaData.getColumnCount();
            Vector columnNames = new Vector();

            for (int column = 0; column < numberOfColumns; column++) {
                columnNames.addElement(metaData.getColumnLabel(column + 1));
            }

            Vector rows = new Vector();

            while (resultSet.next()) {
                Vector newRow = new Vector();

                for (int i = 1; i <= numberOfColumns; i++) {
                    newRow.addElement(resultSet.getObject(i));
                }

                rows.addElement(newRow);
            }
            
            DefaultTableModel resultTableModel = new DefaultTableModel(rows, columnNames);

            return resultTableModel;
        }
        
        
        public DefaultListModel toListModel() throws SQLException {
        //Note: The assumption is that the list elements reside in the last column
            
            if (resultSet == null || dbConnection == null) 
                return null;            
            
            DefaultListModel resultListModel = new DefaultListModel();
            
            ResultSetMetaData metaData = resultSet.getMetaData();
            int maxColumns = metaData.getColumnCount();
            
            
            while (resultSet.next()) {                
                resultListModel.addElement(resultSet.getObject(maxColumns));
            }

            return resultListModel;
        }
        
        public DefaultTreeModel toTreeModel() throws SQLException {
        //Note: the table has to have first 2 rows of type integer, named (id, parentid)

            if (resultSet == null || dbConnection == null) 
                return null;
            
            DefaultTreeModel resultTreeModel = new DefaultTreeModel(new DefaultMutableTreeNode("Resultset"));
            return resultTreeModel;
        }

        public void toXLSX(String fileName) throws SQLException {

            if (resultSet == null || dbConnection == null) 
                return;
            
            ResultSetMetaData metaData = resultSet.getMetaData();
            int numberOfColumns = metaData.getColumnCount();
            
            Workbook excelWorkbook = new XSSFWorkbook();
            System.out.println("Save as file: " + fileName);
            try {
                prepareFile(fileName);
                FileOutputStream fileOutStream = new FileOutputStream(fileName);                
                Sheet sheet = excelWorkbook.createSheet(fileName.replaceAll("[:\\\\////]", "."));
                Row headerRow = sheet.createRow(0);   
                for (int i=0; i<numberOfColumns;i++) {
                    Cell headerCell = headerRow.createCell(i);
                    headerCell.setCellValue(metaData.getColumnName(i+1));
                }
                int rowNum = 1;
                while (resultSet.next()) {
                    Row row = sheet.createRow(rowNum);
                    for (int colNum=1; colNum <= numberOfColumns; colNum++) {
                        Cell cell = row.createCell(colNum-1);
                            cell.setCellValue(String.valueOf(resultSet.getObject(colNum)));
                    }
                    rowNum++;
                }
                
                excelWorkbook.write(fileOutStream);
                fileOutStream.close();

            } catch (Exception ex) {
                Logger.getLogger(SqliteDbConnector.class.getName()).log(Level.SEVERE, null, ex);
            }                                                                
        }
        
        public void toDOCX(String fileName) throws SQLException {

            if (resultSet == null || dbConnection == null) 
                return;
            
            ResultSetMetaData metaData = resultSet.getMetaData();
            int numberOfColumns = metaData.getColumnCount();
            
            System.out.println("Save as file: " + fileName);
            try {
                prepareFile(fileName);
                FileOutputStream fileOutStream = new FileOutputStream(fileName);                
                XWPFDocument wordDocument = new XWPFDocument();   
                
                while (resultSet.next()) {
                    String row = "";
                    for (int colNum=1; colNum <= numberOfColumns; colNum++) {
                        row += String.valueOf(resultSet.getObject(colNum));
                    }
                    if (row.length()==0 || row == null) continue;
                    XWPFParagraph tmpParagraph = wordDocument.createParagraph();
                    XWPFRun tmpRun = tmpParagraph.createRun();   
                    tmpRun.setText(row);
                    tmpRun.setFontSize(8);
                    tmpRun.setFontFamily("Courier New");                    
                }                
                wordDocument.write(fileOutStream);
                fileOutStream.close();
            } catch (Exception ex) {
                Logger.getLogger(SqliteDbConnector.class.getName()).log(Level.SEVERE, null, ex);
            }  

            
        }
    }
}
