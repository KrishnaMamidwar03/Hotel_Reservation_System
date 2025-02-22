
package com.book.DTO;

public class CityDto {
    private String code;
    private String name;
    private String stateCode;
    private CityDto() {
    }
    
	public CityDto(String code, String name, String stateCode) {
		super();
		this.code = code;
		this.name = name;
		this.stateCode = stateCode;
	}
	public String getCode() {
		return code;
	}
	public void setCode(String code) {
		this.code = code;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getStateCode() {
		return stateCode;
	}
	public void setStateCode(String stateCode) {
		this.stateCode = stateCode;
	}

    // Getters and Setters
}



