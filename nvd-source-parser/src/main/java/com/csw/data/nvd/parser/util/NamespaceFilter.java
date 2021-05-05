package com.csw.data.nvd.parser.util;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.XMLFilterImpl;


public class NamespaceFilter extends XMLFilterImpl{

   /* @Autowired
    private SAXConnector saxConnector;

    @Override
    public void startElement(String uri, String localName, String qName, Attributes atts) throws SAXException {
        if(saxConnector != null) {
            Collection<QName> expected = saxConnector.getContext().getCurrentExpectedElements();
            for(QName expectedQname : expected) {
                if(localName.equals(expectedQname.getLocalPart())) {
                    if(expectedQname.equals("Mitigation")) {
                        System.out.println(expectedQname.getNamespaceURI());
                    }
                    super.startElement(expectedQname.getNamespaceURI(), localName, qName, atts);
                    return;
                }
            }
        }
        super.startElement(uri, localName, qName, atts);
    }

    @Override
    public void setContentHandler(ContentHandler handler) {
        super.setContentHandler(handler);
        if(handler instanceof SAXConnector) {
            saxConnector = (SAXConnector) handler;
        }
    }*/

    private String usedNamespaceUri;
    private boolean addNamespace;

    //State variable
    private boolean addedNamespace = false;

    public NamespaceFilter(String namespaceUri,
                           boolean addNamespace) {
        super();

        if (addNamespace)
            this.usedNamespaceUri = namespaceUri;
        else
            this.usedNamespaceUri = "";
        this.addNamespace = addNamespace;
    }



    @Override
    public void startDocument() throws SAXException {
        super.startDocument();
        if (addNamespace) {
            startControlledPrefixMapping();
        }
    }



    @Override
    public void startElement(String arg0, String arg1, String arg2,
                             Attributes arg3) throws SAXException {

        super.startElement(this.usedNamespaceUri, arg1, arg2, arg3);
    }

    @Override
    public void endElement(String arg0, String arg1, String arg2)
            throws SAXException {

        super.endElement(this.usedNamespaceUri, arg1, arg2);
    }

    @Override
    public void startPrefixMapping(String prefix, String url)
            throws SAXException {


        if (addNamespace) {
            this.startControlledPrefixMapping();
        } else {
            //Remove the namespace, i.e. don´t call startPrefixMapping for parent!
        }

    }

    private void startControlledPrefixMapping() throws SAXException {

        if (this.addNamespace && !this.addedNamespace) {
            //We should add namespace since it is set and has not yet been done.
            super.startPrefixMapping("", this.usedNamespaceUri);

            //Make sure we dont do it twice
            this.addedNamespace = true;
        }
    }

}
