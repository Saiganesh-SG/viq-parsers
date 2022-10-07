package com.csw.data.nvd.json.source;

import java.util.HashMap;
import java.util.Map;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;


/**
 * JSON Schema for Common Vulnerability Scoring System version 3.x
 * <p>
 * 
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
	"version",
    "vectorString",
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
    "baseScore",
    "baseSeverity"
})
@Generated("jsonschema2pojo")
public class CvssV3X {

	@JsonProperty("version")
    private String version;
	@JsonProperty("vectorString")
    private String vectorString;
    @JsonProperty("attackVector")
    private CvssV3X.AttackVectorType attackVector;
    @JsonProperty("attackComplexity")
    private CvssV3X.AttackComplexityType attackComplexity;
    @JsonProperty("privilegesRequired")
    private CvssV3X.PrivilegesRequiredType privilegesRequired;
    @JsonProperty("userInteraction")
    private CvssV3X.UserInteractionType userInteraction;
    @JsonProperty("scope")
    private CvssV3X.ScopeType scope;
    @JsonProperty("confidentialityImpact")
    private CvssV3X.CiaType confidentialityImpact;
    @JsonProperty("integrityImpact")
    private CvssV3X.CiaType integrityImpact;
    @JsonProperty("availabilityImpact")
    private CvssV3X.CiaType availabilityImpact;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("baseScore")
    private Double baseScore;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("baseSeverity")
    private CvssV3X.SeverityType baseSeverity;

    @JsonProperty("attackVector")
    public CvssV3X.AttackVectorType getAttackVector() {
        return attackVector;
    }

    @JsonProperty("attackVector")
    public void setAttackVector(CvssV3X.AttackVectorType attackVector) {
        this.attackVector = attackVector;
    }

    @JsonProperty("attackComplexity")
    public CvssV3X.AttackComplexityType getAttackComplexity() {
        return attackComplexity;
    }

    @JsonProperty("attackComplexity")
    public void setAttackComplexity(CvssV3X.AttackComplexityType attackComplexity) {
        this.attackComplexity = attackComplexity;
    }

    @JsonProperty("privilegesRequired")
    public CvssV3X.PrivilegesRequiredType getPrivilegesRequired() {
        return privilegesRequired;
    }

    @JsonProperty("privilegesRequired")
    public void setPrivilegesRequired(CvssV3X.PrivilegesRequiredType privilegesRequired) {
        this.privilegesRequired = privilegesRequired;
    }

    @JsonProperty("userInteraction")
    public CvssV3X.UserInteractionType getUserInteraction() {
        return userInteraction;
    }

    @JsonProperty("userInteraction")
    public void setUserInteraction(CvssV3X.UserInteractionType userInteraction) {
        this.userInteraction = userInteraction;
    }

    @JsonProperty("scope")
    public CvssV3X.ScopeType getScope() {
        return scope;
    }

    @JsonProperty("scope")
    public void setScope(CvssV3X.ScopeType scope) {
        this.scope = scope;
    }

    @JsonProperty("confidentialityImpact")
    public CvssV3X.CiaType getConfidentialityImpact() {
        return confidentialityImpact;
    }

    @JsonProperty("confidentialityImpact")
    public void setConfidentialityImpact(CvssV3X.CiaType confidentialityImpact) {
        this.confidentialityImpact = confidentialityImpact;
    }

    @JsonProperty("integrityImpact")
    public CvssV3X.CiaType getIntegrityImpact() {
        return integrityImpact;
    }

    @JsonProperty("integrityImpact")
    public void setIntegrityImpact(CvssV3X.CiaType integrityImpact) {
        this.integrityImpact = integrityImpact;
    }

    @JsonProperty("availabilityImpact")
    public CvssV3X.CiaType getAvailabilityImpact() {
        return availabilityImpact;
    }

    @JsonProperty("availabilityImpact")
    public void setAvailabilityImpact(CvssV3X.CiaType availabilityImpact) {
        this.availabilityImpact = availabilityImpact;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("baseScore")
    public Double getBaseScore() {
        return baseScore;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("baseScore")
    public void setBaseScore(Double baseScore) {
        this.baseScore = baseScore;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("baseSeverity")
    public CvssV3X.SeverityType getBaseSeverity() {
        return baseSeverity;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("baseSeverity")
    public void setBaseSeverity(CvssV3X.SeverityType baseSeverity) {
        this.baseSeverity = baseSeverity;
    }
    
    public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getVectorString() {
		return vectorString;
	}

	public void setVectorString(String vectorString) {
		this.vectorString = vectorString;
	}

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(CvssV3X.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("attackVector");
        sb.append('=');
        sb.append(((this.attackVector == null)?"<null>":this.attackVector));
        sb.append(',');
        sb.append("attackComplexity");
        sb.append('=');
        sb.append(((this.attackComplexity == null)?"<null>":this.attackComplexity));
        sb.append(',');
        sb.append("privilegesRequired");
        sb.append('=');
        sb.append(((this.privilegesRequired == null)?"<null>":this.privilegesRequired));
        sb.append(',');
        sb.append("userInteraction");
        sb.append('=');
        sb.append(((this.userInteraction == null)?"<null>":this.userInteraction));
        sb.append(',');
        sb.append("scope");
        sb.append('=');
        sb.append(((this.scope == null)?"<null>":this.scope));
        sb.append(',');
        sb.append("confidentialityImpact");
        sb.append('=');
        sb.append(((this.confidentialityImpact == null)?"<null>":this.confidentialityImpact));
        sb.append(',');
        sb.append("integrityImpact");
        sb.append('=');
        sb.append(((this.integrityImpact == null)?"<null>":this.integrityImpact));
        sb.append(',');
        sb.append("availabilityImpact");
        sb.append('=');
        sb.append(((this.availabilityImpact == null)?"<null>":this.availabilityImpact));
        sb.append(',');
        sb.append("baseScore");
        sb.append('=');
        sb.append(((this.baseScore == null)?"<null>":this.baseScore));
        sb.append(',');
        sb.append("baseSeverity");
        sb.append('=');
        sb.append(((this.baseSeverity == null)?"<null>":this.baseSeverity));
        sb.append(',');
        if (sb.charAt((sb.length()- 1)) == ',') {
            sb.setCharAt((sb.length()- 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result* 31)+((this.baseSeverity == null)? 0 :this.baseSeverity.hashCode()));
        result = ((result* 31)+((this.confidentialityImpact == null)? 0 :this.confidentialityImpact.hashCode()));
        result = ((result* 31)+((this.attackComplexity == null)? 0 :this.attackComplexity.hashCode()));
        result = ((result* 31)+((this.scope == null)? 0 :this.scope.hashCode()));
        result = ((result* 31)+((this.attackVector == null)? 0 :this.attackVector.hashCode()));
        result = ((result* 31)+((this.availabilityImpact == null)? 0 :this.availabilityImpact.hashCode()));
        result = ((result* 31)+((this.integrityImpact == null)? 0 :this.integrityImpact.hashCode()));
        result = ((result* 31)+((this.privilegesRequired == null)? 0 :this.privilegesRequired.hashCode()));
        result = ((result* 31)+((this.baseScore == null)? 0 :this.baseScore.hashCode()));
        result = ((result* 31)+((this.userInteraction == null)? 0 :this.userInteraction.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof CvssV3X) == false) {
            return false;
        }
        CvssV3X rhs = ((CvssV3X) other);
        return (((((((((((this.baseSeverity == rhs.baseSeverity)||((this.baseSeverity!= null)&&this.baseSeverity.equals(rhs.baseSeverity)))&&((this.confidentialityImpact == rhs.confidentialityImpact)||((this.confidentialityImpact!= null)&&this.confidentialityImpact.equals(rhs.confidentialityImpact))))&&((this.attackComplexity == rhs.attackComplexity)||((this.attackComplexity!= null)&&this.attackComplexity.equals(rhs.attackComplexity))))&&((this.scope == rhs.scope)||((this.scope!= null)&&this.scope.equals(rhs.scope))))&&((this.attackVector == rhs.attackVector)||((this.attackVector!= null)&&this.attackVector.equals(rhs.attackVector))))&&((this.availabilityImpact == rhs.availabilityImpact)||((this.availabilityImpact!= null)&&this.availabilityImpact.equals(rhs.availabilityImpact))))&&((this.integrityImpact == rhs.integrityImpact)||((this.integrityImpact!= null)&&this.integrityImpact.equals(rhs.integrityImpact))))&&((this.privilegesRequired == rhs.privilegesRequired)||((this.privilegesRequired!= null)&&this.privilegesRequired.equals(rhs.privilegesRequired))))&&((this.baseScore == rhs.baseScore)||((this.baseScore!= null)&&this.baseScore.equals(rhs.baseScore))))&&((this.userInteraction == rhs.userInteraction)||((this.userInteraction!= null)&&this.userInteraction.equals(rhs.userInteraction))));
    }

    @Generated("jsonschema2pojo")
    public enum AttackComplexityType {

        HIGH("HIGH"),
        LOW("LOW");
        private final String value;
        private final static Map<String, CvssV3X.AttackComplexityType> CONSTANTS = new HashMap<String, CvssV3X.AttackComplexityType>();

        static {
            for (CvssV3X.AttackComplexityType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private AttackComplexityType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.AttackComplexityType fromValue(String value) {
            CvssV3X.AttackComplexityType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    @Generated("jsonschema2pojo")
    public enum AttackVectorType {

        NETWORK("NETWORK"),
        ADJACENT("ADJACENT"),
        LOCAL("LOCAL"),
        PHYSICAL("PHYSICAL");
        private final String value;
        private final static Map<String, CvssV3X.AttackVectorType> CONSTANTS = new HashMap<String, CvssV3X.AttackVectorType>();

        static {
            for (CvssV3X.AttackVectorType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private AttackVectorType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.AttackVectorType fromValue(String value) {
            CvssV3X.AttackVectorType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    @Generated("jsonschema2pojo")
    public enum CiaType {

        NONE("NONE"),
        LOW("LOW"),
        HIGH("HIGH");
        private final String value;
        private final static Map<String, CvssV3X.CiaType> CONSTANTS = new HashMap<String, CvssV3X.CiaType>();

        static {
            for (CvssV3X.CiaType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private CiaType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.CiaType fromValue(String value) {
            CvssV3X.CiaType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    @Generated("jsonschema2pojo")
    public enum PrivilegesRequiredType {

        HIGH("HIGH"),
        LOW("LOW"),
        NONE("NONE");
        private final String value;
        private final static Map<String, CvssV3X.PrivilegesRequiredType> CONSTANTS = new HashMap<String, CvssV3X.PrivilegesRequiredType>();

        static {
            for (CvssV3X.PrivilegesRequiredType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private PrivilegesRequiredType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.PrivilegesRequiredType fromValue(String value) {
            CvssV3X.PrivilegesRequiredType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    @Generated("jsonschema2pojo")
    public enum ScopeType {

        UNCHANGED("UNCHANGED"),
        CHANGED("CHANGED");
        private final String value;
        private final static Map<String, CvssV3X.ScopeType> CONSTANTS = new HashMap<String, CvssV3X.ScopeType>();

        static {
            for (CvssV3X.ScopeType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private ScopeType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.ScopeType fromValue(String value) {
            CvssV3X.ScopeType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    @Generated("jsonschema2pojo")
    public enum SeverityType {

        NONE("NONE"),
        LOW("LOW"),
        MEDIUM("MEDIUM"),
        HIGH("HIGH"),
        CRITICAL("CRITICAL");
        private final String value;
        private final static Map<String, CvssV3X.SeverityType> CONSTANTS = new HashMap<String, CvssV3X.SeverityType>();

        static {
            for (CvssV3X.SeverityType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private SeverityType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.SeverityType fromValue(String value) {
            CvssV3X.SeverityType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    @Generated("jsonschema2pojo")
    public enum UserInteractionType {

        NONE("NONE"),
        REQUIRED("REQUIRED");
        private final String value;
        private final static Map<String, CvssV3X.UserInteractionType> CONSTANTS = new HashMap<String, CvssV3X.UserInteractionType>();

        static {
            for (CvssV3X.UserInteractionType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private UserInteractionType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static CvssV3X.UserInteractionType fromValue(String value) {
            CvssV3X.UserInteractionType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

}
