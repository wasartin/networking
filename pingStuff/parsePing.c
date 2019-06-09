#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

int pos(char *line, const char *target, int offset);
void get_avg_in_file(char *filepath);
char *filepath_concat(const char *home, const char *directory);
char *extract_substring(char * line, const char *begin,
			const char *end, int offset);

int main(int argc, char *argv[]){
  if(argc == 1){
    printf("No file given\n");
    return -1;
  }

  //run everything in this directory
  if(argv[1][0] == '-' && argv[1][1] == 'd' && argc > 2){
    //get file path
    //char *home = getenv("HOME");
    char *given = argv[2];
    
    //get all the contents of the directory
    struct dirent *directory;
    DIR *dr = opendir(given);
    if(dr == NULL){
      printf("Could not open: %s\n", given);
      //free(filePath);
      return -404;
    }
    while((directory = readdir(dr)) != NULL){
      char *currFileName = directory->d_name;
      if(currFileName[0] != '.'){
	//printf("File: %s\n", directory->d_name);
	
	get_avg_in_file(currFileName);
      }

    }
    
    closedir(dr);
    //free(filePath);
    return 0;
  }

  /*
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
  printf("Ran file: %s\n", argv[1]);
  printf("Running total was %f\n", runningTotal);
  printf("Total input of %d, and average value of: %0.3f\n", numOfLines, avg);
  printf("==================================================\n\n");
  */
  
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

int last_index_of(char *line, const char target){
  int i;
  for(i = strlen(line) - 1; i > -1; i--){
    if(target == line[i]){
      return i;
    }
  }
  return -2;
}

char *extract_substring(char * line, const char *begin,
			const char *end, int offset){
  char input[strlen(line)];
  memcpy(input, line+offset, strlen(line - offset + 1));
  return NULL;
}

char *filepath_concat(const char *directory, const char *fileName){
  //currently the input is cwd (47) + file name + /
  char *s0 = malloc(strlen(directory) + strlen(fileName) + 1); //+1 for nullbit
  strcpy(s0, directory);
  strcat(s0, fileName);
  return s0;
}

//Need the address for this thing.
void get_avg_in_file(char *filePath){
  //for now
  char *front = "/home/will/summer19/networking/pingStuff/data/";
  FILE *fp;
  
  static char buffer[1024];
  char *path = filepath_concat(front, filePath);
  
  fp=fopen(path, "r");
  
  int numOfLines = 0;
  float runningTotal = 0;

  static const char *target = "time=";

  while(fgets(buffer, 1024, fp)){
    //Get the Section I want
    //printf("%s", line);
    numOfLines++;
    if(numOfLines == 100){
      break;
    }
    int timePos  = pos(buffer, target, 4);
    int endPos = last_index_of(buffer, ' ');
    if(timePos != -1){
      int length = endPos - timePos;
      char section[length + 1];//for null byte
      memmove(section, &buffer[timePos], length);
      section[length + 1] ='\0';
      //    printf("7th in List: %s\n", hope);
      
      //Extract the value out
      int valuePart = pos(section, "=", 1) + 1;
      int newLength = length - valuePart;
      char part2[newLength + 1]; //removing the 'time='.... techdebt right here baby
      memmove(part2, &section[valuePart], newLength);
      part2[newLength + 1] = '\0';
      //printf("Is this the number?: %s\n", part2);
      //convert string value into float
      float currValue = atof(part2);
      runningTotal+= currValue; 
    }
  }
  fclose(fp);
  float avg = -1;
  float tempLines = numOfLines;
  avg = runningTotal / tempLines;
  printf("Ran file: %s\n", path);
  printf("Running total was %f\n", runningTotal);
  printf("Total input of %d, and average value of: %0.3f\n", numOfLines, avg);
  printf("==================================================\n\n");

  free(path);
}
