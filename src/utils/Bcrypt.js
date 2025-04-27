import bcrypt from "bcrypt"

export const bcryptHash = async(data)=>{
    const hashedData = await bcrypt.hash(data, 10);
    return hashedData;
};

export const bcryptCompare = async(normalData, hashedData)=>{
    const compareResult = await bcrypt.compare(normalData, hashedData);
    return compareResult;
}


