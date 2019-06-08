#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int pos(char *line, const char *target, int offset);

char *extract_substring(char * line, const char *begin,
			const char *end, int offset);

int main(int argc, char *argv[]){
  if(argc == 1){
    printf("No file given\n");
    return -1;
  }
  
  FILE *fp;
  static char buffer[1024];
  
  fp=fopen(argv[1], "r");
  
  int numOfLines = 0;
  float runningTotal = 0;

  static const char *target = "time=";

  while(fgets(buffer, 1024, fp)){
    //Get the Section I want
    //printf("%s", line);
    numOfLines++;
    int timePos  = pos(buffer, target, 4);
    char section[11];
    memmove(section, &buffer[timePos], 11);
    section[11] ='\0';
    //    printf("7th in List: %s\n", hope);
    
    //Extract the value out
    int valuePart = pos(section, "=", 1) + 1;
    char part2[6];
    memmove(part2, &section[valuePart], 5);
    part2[6] = '\0';
    //printf("Is this the number?: %s\n", part2);

    //convert string value into float
    float currValue = atof(part2);
    runningTotal+= currValue;
  }
  fclose(fp);
  float avg = -1;
  float tempLines = numOfLines;
  avg = runningTotal / tempLines;
  
  printf("Running total was %f\n", runningTotal);
  printf("Total input of %d, and average value of: %0.3f\n", numOfLines, avg);
  
  return 0; 
}

int pos(char *line, const char *target, int offset){
  char input[strlen(line)];
  memcpy(input, line+offset, strlen(line)-offset + 1);
  char *p = strstr(input, target);
  if(p){
    return p - input+offset;
  }
  return -1;
}

char *extract_substring(char * line, const char *begin,
			const char *end, int offset){
  char input[strlen(line)];
  memcpy(input, line+offset, strlen(line - offset + 1));
  return NULL;
}
